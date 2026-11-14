<?php

/**
 * Tests without PHPUnit:  php tests/run.php
 * Against a real server too: ARIONPAY_IT_BASE_URL=... ARIONPAY_IT_API_KEY=... ARIONPAY_IT_API_SECRET=...
 *                            ARIONPAY_IT_WEBHOOK_SECRET=... ARIONPAY_IT_HOOK_PORT=18099 php tests/run.php
 */

declare(strict_types=1);

require __DIR__ . '/../autoload.php';

use ArionPay\ApiException;
use ArionPay\Client;
use ArionPay\Signature;
use ArionPay\SignatureException;
use ArionPay\Webhook;

error_reporting(E_ALL);
set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
    if (!(error_reporting() & $no)) {
        return false; // silenced with @ (e.g. an accept() that timed out while waiting for a webhook)
    }
    throw new ErrorException($msg, 0, $no, $file, $line);
});

$passed = 0;
$failed = 0;
function check(string $name, callable $fn): void
{
    global $passed, $failed;
    try {
        $fn();
        $passed++;
        echo "ok - $name\n";
    } catch (Throwable $e) {
        $failed++;
        echo "not ok - $name\n  " . get_class($e) . ': ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ")\n";
    }
}
function same($expected, $actual, string $what = ''): void
{
    if ($expected !== $actual) {
        throw new RuntimeException("$what expected " . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}
function throwsLike(string $class, callable $fn, string $pattern = ''): void
{
    try {
        $fn();
    } catch (Throwable $e) {
        if (!$e instanceof $class) {
            throw new RuntimeException("expected $class, got " . get_class($e) . ': ' . $e->getMessage());
        }
        if ($pattern !== '' && !preg_match($pattern, $e->getMessage())) {
            throw new RuntimeException("message '" . $e->getMessage() . "' does not match $pattern");
        }
        return;
    }
    throw new RuntimeException("expected $class, nothing thrown");
}

const SECRET = 'whsec_unit_0001';
function signed(string $body, ?int $t = null, string $secret = SECRET): string
{
    $t = $t ?? time();
    return 't=' . $t . ',v1=' . hash_hmac('sha256', $t . '.' . $body, $secret);
}
$event = ['id' => 'evt_abc', 'type' => 'invoice.paid', 'created' => 1, 'livemode' => true, 'data' => ['invoice' => ['id' => '6af75d7ce83f10cb386f0981', 'status' => 'paid']]];

// ---------------------------------------------------------------- signatures (vectors computed with Python hmac)

check('request signatures match fixed vectors', function () {
    same('e6855fc36dc68ee45a227f7bfff6965585803c9530238b1b771746c118a91770', Signature::signRequest('sk_x', 1700000000, 'POST', '/api/v1/invoices', '{"a":1}'));
    same('76c4e503c0883422e6c050aef0becffba060d8814f3a8f95c604dc1914639ef2', Signature::signRequest('sk_x', 1700000000, 'get', '/api/v1/invoices/abc?x=1', 'ignored'));
});

check('webhook vector with non-ASCII body', function () {
    $body = '{"id":"evt_1","d":"Café ☕"}';
    same(true, Signature::isValidWebhook($body, 't=1700000000,v1=b46713ea18763393136a4349ad8360ef626037d03661a1bba100504ed019acba', SECRET, 300, 1700000100));
});

check('header parsing', function () {
    $v1 = str_repeat('a', 64);
    same(['t' => 123, 'v1' => $v1], Signature::parseHeader("t=123,v1=$v1"));
    same(['t' => 5, 'v1' => $v1], Signature::parseHeader(' v1=' . strtoupper($v1) . ' , t=5 '));
    foreach (['', null, 't=1', "v1=$v1", "t=x,v1=$v1", 't=1,v1=zz', "t=1,v1={$v1}0"] as $bad) {
        same(null, Signature::parseHeader($bad), var_export($bad, true));
    }
});

check('valid webhook passes', function () use ($event) {
    $body = json_encode($event);
    same('evt_abc', Webhook::verify($body, signed($body), SECRET)['id']);
});

check('tampered, re-encoded, wrong secret, stale, future webhooks fail', function () use ($event) {
    $body = json_encode($event);
    $h = signed($body);
    throwsLike(SignatureException::class, function () use ($body, $h) { Webhook::verify(str_replace('paid', 'PAID', $body), $h, SECRET); });
    throwsLike(SignatureException::class, function () use ($body, $h) { Webhook::verify(json_encode(json_decode($body, true), JSON_PRETTY_PRINT), $h, SECRET); });
    throwsLike(SignatureException::class, function () use ($body, $h) { Webhook::verify($body, $h, 'whsec_other'); });
    throwsLike(SignatureException::class, function () use ($body, $h) { Webhook::verify($body, $h, ''); }, '/empty/');
    $old = time() - 301;
    throwsLike(SignatureException::class, function () use ($body, $old) { Webhook::verify($body, signed($body, $old), SECRET); }, '/stale/');
    throwsLike(SignatureException::class, function () use ($body, $old) { Webhook::verify($body, signed($body, $old + 602), SECRET); }, '/stale/');
    same(true, Signature::isValidWebhook($body, signed($body, $old), SECRET, 600));
    throwsLike(SignatureException::class, function () use ($body) { Webhook::verify($body, '', SECRET); }, '/Missing or malformed/');
});

check('signed but not an event is refused', function () {
    foreach (['not json', '{}', '[]', '{"id":"","type":"invoice.paid","data":{"invoice":{}}}', '{"id":"evt_1","type":"invoice.paid"}', '{"id":"evt_1","type":"invoice.paid","data":{"invoice":null}}'] as $body) {
        throwsLike(SignatureException::class, function () use ($body) { Webhook::verify($body, signed($body), SECRET); });
    }
});

check('test events are recognised', function () use ($event) {
    same(true, Webhook::isTestEvent($event + ['test' => true]));
    same(true, Webhook::isTestEvent(['id' => 'evt_test_1'] + $event));
    same(true, Webhook::isTestEvent(['data' => ['invoice' => ['id' => 'inv_test_x']]] + $event));
    same(false, Webhook::isTestEvent($event));
});

// ---------------------------------------------------------------- client with a fake transport

final class FakeTransport
{
    /** @var array<int,mixed> */
    public $answers;
    /** @var array<int,array<string,mixed>> */
    public $calls = [];

    public function __construct(array $answers)
    {
        $this->answers = $answers;
    }

    public function __invoke(string $method, string $url, array $headers, ?string $body, int $timeout): array
    {
        $this->calls[] = compact('method', 'url', 'headers', 'body');
        $a = array_shift($this->answers);
        if ($a === null) {
            throw new RuntimeException('no more answers');
        }
        if ($a instanceof Throwable) {
            throw $a;
        }
        return [$a[0], json_encode($a[1])];
    }
}
function client(FakeTransport $t, array $opts = []): Client
{
    return new Client('pk_unit_000001', 'sk_unit', $opts + ['baseUrl' => 'https://example.test/', 'transport' => $t]);
}

check('constructor checks', function () {
    throwsLike(InvalidArgumentException::class, function () { new Client('nope', 's'); }, '/pk_/');
    throwsLike(InvalidArgumentException::class, function () { new Client('pk_abcdefgh', ''); }, '/apiSecret/');
    throwsLike(InvalidArgumentException::class, function () { new Client('pk_abcdefgh', 's', ['baseUrl' => 'ftp://x']); }, '/http/');
});

check('createInvoice signs the exact body and maps the answer', function () {
    $id = str_repeat('a', 24);
    $t = new FakeTransport([[201, ['status' => 'success', 'id' => $id, 'invoice_url' => 'https://x/pay/1', 'data' => ['id' => $id, 'invoice_url' => 'https://x/pay/1', 'amount_fiat' => 9.5, 'currency' => 'EUR', 'status' => 'new', 'order_id' => '7']]]]);
    $inv = client($t)->createInvoice(['amount' => 9.5, 'currency' => 'EUR', 'orderId' => '7', 'description' => null, 'metadata' => ['name' => 'Zoë/1']]);
    same('https://x/pay/1', $inv['invoiceUrl']);
    $c = $t->calls[0];
    same('https://example.test/api/v1/invoices', $c['url']);
    $body = json_decode($c['body'], true);
    same('9.5', $body['amount']);
    same(false, array_key_exists('description', $body));
    same(1, preg_match('/^sdk_[0-9a-f]{32}$/', $body['idempotencyKey']));
    same(false, strpos($c['body'], '\\/') !== false || strpos($c['body'], '\\u00eb') !== false, 'unescaped slashes and unicode');
    same(hash_hmac('sha256', $c['headers']['x-timestamp'] . '.' . $c['body'], 'sk_unit'), $c['headers']['x-signature']);
});

check('amounts are sent as plain decimal strings', function () {
    foreach ([[10, '10'], [0.1, '0.1'], [19.99, '19.99'], [1e-7, '0.0000001'], ['  5.00 ', '5.00']] as [$in, $out]) {
        $t = new FakeTransport([[201, ['id' => str_repeat('a', 24), 'invoice_url' => 'u', 'data' => []]]]);
        client($t)->createInvoice(['amount' => $in]);
        same($out, json_decode($t->calls[0]['body'], true)['amount'], var_export($in, true));
    }
});

check('unknown or snake_case fields are refused before sending', function () {
    $t = new FakeTransport([]);
    throwsLike(InvalidArgumentException::class, function () use ($t) { client($t)->createInvoice(['amount' => 1, 'order_id' => 'x']); }, '/order_id/');
    same([], $t->calls);
});

check('GET is signed over the path, including a base path', function () {
    $id = str_repeat('b', 24);
    $t = new FakeTransport([[200, ['invoiceId' => $id, 'status' => 'PAID', 'amountFiat' => 1, 'currency' => 'USD', 'test' => true]]]);
    $inv = client($t, ['baseUrl' => 'https://example.test/gw/'])->getInvoice($id);
    same('paid', $inv['status']);
    same(true, $inv['test']);
    $c = $t->calls[0];
    same("https://example.test/gw/api/v1/invoices/$id", $c['url']);
    same(hash_hmac('sha256', $c['headers']['x-timestamp'] . ".GET /gw/api/v1/invoices/$id", 'sk_unit'), $c['headers']['x-signature']);
});

check('a replayed signature is signed again once', function () {
    $id = str_repeat('c', 24);
    $t = new FakeTransport([[401, ['error' => 'This signed request was already used. Sign each request with a fresh timestamp.']], [200, ['invoiceId' => $id, 'status' => 'NEW']]]);
    same('new', client($t)->getInvoice($id)['status']);
    same(2, count($t->calls));
    same(true, $t->calls[0]['headers']['x-timestamp'] !== $t->calls[1]['headers']['x-timestamp']);
});

check('createInvoice retries a network error with the same idempotency key', function () {
    $t = new FakeTransport([new RuntimeException('connection refused'), [201, ['id' => str_repeat('d', 24), 'invoice_url' => 'u', 'data' => []]]]);
    client($t)->createInvoice(['amount' => '1']);
    same(2, count($t->calls));
    same(json_decode($t->calls[0]['body'], true)['idempotencyKey'], json_decode($t->calls[1]['body'], true)['idempotencyKey']);
});

check('simulate is not retried; errors carry status and code', function () {
    $t = new FakeTransport([[503, ['error' => 'busy']]]);
    try {
        client($t)->simulatePayment(str_repeat('e', 24), 'exact');
        throw new RuntimeException('no exception');
    } catch (ApiException $e) {
        same(503, $e->getStatus());
    }
    same(1, count($t->calls));
    $t = new FakeTransport([[409, ['error' => 'This Idempotency-Key was already used', 'code' => 'idempotency_key_reused']]]);
    try {
        client($t)->createInvoice(['amount' => '1', 'idempotencyKey' => 'k']);
        throw new RuntimeException('no exception');
    } catch (ApiException $e) {
        same([409, 'idempotency_key_reused'], [$e->getStatus(), $e->getApiCode()]);
    }
    same(1, count($t->calls));
});

check('an unreachable server gives status 0 after the allowed attempts', function () {
    $t = new FakeTransport([new RuntimeException('down'), new RuntimeException('down')]);
    try {
        client($t, ['maxAttempts' => 2])->getInvoice(str_repeat('f', 24));
        throw new RuntimeException('no exception');
    } catch (ApiException $e) {
        same(0, $e->getStatus());
        same(1, preg_match('/Could not reach/', $e->getMessage()));
    }
    same(2, count($t->calls));
});

check('bad input never reaches the network', function () {
    $t = new FakeTransport([]);
    throwsLike(InvalidArgumentException::class, function () use ($t) { client($t)->getInvoice('../admin'); });
    throwsLike(InvalidArgumentException::class, function () use ($t) { client($t)->simulatePayment(str_repeat('a', 24), 'free_money'); });
    throwsLike(InvalidArgumentException::class, function () use ($t) { client($t)->createInvoice([]); });
    same([], $t->calls);
});

// ---------------------------------------------------------------- real server (optional)

$base = getenv('ARIONPAY_IT_BASE_URL');
if ($base) {
    check('real server: sandbox payment with a real signed webhook, over cURL and over streams', function () use ($base) {
        $port = (int) (getenv('ARIONPAY_IT_HOOK_PORT') ?: 18099);
        $secret = (string) getenv('ARIONPAY_IT_WEBHOOK_SECRET');
        $ap = new Client((string) getenv('ARIONPAY_IT_API_KEY'), (string) getenv('ARIONPAY_IT_API_SECRET'), ['baseUrl' => $base, 'webhookSecret' => $secret]);
        $server = stream_socket_server("tcp://127.0.0.1:$port", $errno, $errstr);
        if (!$server) {
            throw new RuntimeException("cannot listen on $port: $errstr");
        }
        $received = [];
        $receive = function (callable $pred, int $seconds = 60) use ($server, $ap, &$received): array {
            $end = time() + $seconds;
            while (time() < $end) {
                foreach ($received as $e) {
                    if ($pred($e)) {
                        return $e;
                    }
                }
                $conn = @stream_socket_accept($server, 1);
                if (!$conn) {
                    continue;
                }
                $head = '';
                while (strpos($head, "\r\n\r\n") === false && !feof($conn)) {
                    $head .= fread($conn, 1);
                }
                preg_match('/content-length:\s*(\d+)/i', $head, $m);
                preg_match('/arionpay-signature:\s*([^\r\n]+)/i', $head, $s);
                $len = (int) ($m[1] ?? 0);
                $body = '';
                while (strlen($body) < $len && !feof($conn)) {
                    $body .= fread($conn, $len - strlen($body));
                }
                try {
                    $received[] = $ap->verifyWebhook($body, $s[1] ?? '');
                    fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                } catch (SignatureException $e) {
                    fwrite($conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
                fclose($conn);
            }
            throw new RuntimeException('webhook not received');
        };

        $found = false;
        foreach ($ap->currencies() as $c) {
            $found = $found || $c['symbol'] === 'USDT_TRC20';
        }
        same(true, $found, 'USDT_TRC20 listed');
        $orderId = 'php-it-' . time();
        $inv = $ap->createInvoice(['amount' => '3.21', 'currency' => 'USD', 'orderId' => $orderId, 'asset' => 'USDT_TRC20', 'test' => true, 'metadata' => ['cart' => 'php'], 'callbackUrl' => "http://127.0.0.1:$port/hook"]);
        same(1, preg_match('/^[0-9a-f]{24}$/', $inv['id']));

        $key = 'php-key-' . time();
        $a = $ap->createInvoice(['amount' => '5', 'orderId' => "$orderId-b", 'idempotencyKey' => $key, 'test' => true]);
        $b = $ap->createInvoice(['amount' => '5', 'orderId' => "$orderId-b", 'idempotencyKey' => $key, 'test' => true]);
        same($a['id'], $b['id']);

        same('new', $ap->getInvoice($inv['id'])['status']);
        $ap->simulatePayment($inv['id'], 'exact');
        $paid = $receive(function ($e) use ($inv) { return $e['type'] === 'invoice.paid' && $e['data']['invoice']['id'] === $inv['id']; });
        same($orderId, $paid['data']['invoice']['orderId']);
        same(true, $paid['data']['invoice']['test']);
        same(['cart' => 'php'], $paid['data']['invoice']['metadata']);

        $read = $ap->getInvoice($inv['id']);
        same('paid', $read['status']);
        same(3.21, $read['amountFiat']);

        $t = $ap->sendTestWebhook('invoice.partial');
        $testEvent = $receive(function ($e) use ($t) { return $e['id'] === ($t['eventId'] ?? ''); });
        same(true, Webhook::isTestEvent($testEvent));

        // the same read over PHP streams instead of cURL
        $streams = new Client((string) getenv('ARIONPAY_IT_API_KEY'), (string) getenv('ARIONPAY_IT_API_SECRET'), [
            'baseUrl' => $base,
            'http' => 'streams',
        ]);
        same('paid', $streams->getInvoice($inv['id'])['status']);
        try {
            $ap->getInvoice(str_repeat('0', 24));
            throw new RuntimeException('no exception');
        } catch (ApiException $e) {
            same(404, $e->getStatus());
        }
        fclose($server);
    });
}

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
