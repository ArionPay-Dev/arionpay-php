# ArionPay for PHP

Official PHP client for [ArionPay](https://arionpay.com). Create crypto invoices, send customers to the payment page, and check webhooks. The money goes straight to your own wallet: ArionPay never holds it.

- PHP 7.4 to 8.5. No dependencies. Uses cURL when installed, PHP streams otherwise.
- Works with Composer, or without it (copy the folder and `require 'autoload.php'`), so it also fits shared hosting.
- Safe retries: every invoice request carries an idempotency key, so a network error can never create two invoices.

```bash
composer require arionpay/arionpay-php
```

Without Composer: download this folder, upload it next to your site, and `require __DIR__ . '/arionpay-php/autoload.php';`.

## Keys

In your ArionPay dashboard, open your store:

| Value | Where | Starts with |
| --- | --- | --- |
| API key | Store page, **API key** | `pk_` |
| API secret | Store page, **API secret** (asks for your authenticator code) | `sk_` |
| Webhook secret | **Webhooks** page, **signing secret** | `whsec_` |

Keep them on your server (for example in environment variables or a config file outside the web root).

## Take a payment

```php
<?php
require 'vendor/autoload.php';

$arionpay = new \ArionPay\Client(getenv('ARIONPAY_API_KEY'), getenv('ARIONPAY_API_SECRET'), [
    'webhookSecret' => getenv('ARIONPAY_WEBHOOK_SECRET'),
]);

$invoice = $arionpay->createInvoice([
    'amount'      => '49.90',
    'currency'    => 'USD',
    'orderId'     => '1001',
    'successUrl'  => 'https://shop.example.com/thanks/1001',
    'cancelUrl'   => 'https://shop.example.com/cart',
    'metadata'    => ['user_id' => 42],
    'idempotencyKey' => 'order-1001-1', // the same key always returns the same invoice (safe on page reloads)
]);

header('Location: ' . $invoice['invoiceUrl'], true, 303);
```

The customer coming back to `successUrl` does **not** prove they paid. Deliver the order when the `invoice.paid` webhook arrives (or when `getInvoice()` says `paid`).

## Webhooks

Set your webhook address on the **Webhooks** page of the dashboard (a public `https://` address on port 443 or 8443), or per invoice with `callbackUrl`.

```php
<?php
// webhook.php
require 'vendor/autoload.php';

use ArionPay\SignatureException;
use ArionPay\Webhook;

try {
    $event = Webhook::fromGlobals(getenv('ARIONPAY_WEBHOOK_SECRET')); // reads the raw body and the ArionPay-Signature header
} catch (SignatureException $e) {
    http_response_code(401);
    exit;
}

if (Webhook::isTestEvent($event)) {        // "Send test webhook": a made-up invoice, never a real order
    exit('{"received":true}');
}
if (already_processed($event['id'])) {      // the same event can arrive more than once
    exit('{"received":true}');
}

$invoice = $event['data']['invoice'];
$order = find_order($invoice['orderId']);

if ($event['type'] === 'invoice.paid' && $order && !$order->paid) {
    $sameTotal = number_format((float) $order->total, 2, '.', '') === number_format((float) $invoice['amountFiat'], 2, '.', '');
    if ($sameTotal && $order->currency === $invoice['currency'] && $invoice['test'] === $order->isTest) {
        mark_order_paid($order, $invoice);  // deliver here
    }
}
remember_processed($event['id']);
echo '{"received":true}';
```

If you read the body yourself, pass it exactly as received: `Webhook::verify(file_get_contents('php://input'), $_SERVER['HTTP_ARIONPAY_SIGNATURE'] ?? '', $secret)`. Do not decode and re-encode it first.

| Event | Meaning | What to do |
| --- | --- | --- |
| `invoice.pending` | A payment was seen on the network and waits for confirmations. | Show "payment on its way". Do not deliver yet. |
| `invoice.partial` | Less than the full amount arrived. The invoice stays open for the rest. | Do not deliver. |
| `invoice.paid` | Fully paid and confirmed. Also sent when you accept a payment by hand in the dashboard. | Deliver the order. |
| `invoice.expired` | Time ran out without full payment. A late payment can still make it `paid`. | Keep the order unpaid. |
| `invoice.needs_review` | Something needs a person, for example more money arrived after the invoice was paid. | Tell a human. Do not change the order. |

ArionPay sends again when your server does not answer `2xx` (for about 3 days).

### Rules for a safe integration

1. Check the signature on the raw body. Never trust a webhook you could not verify.
2. Deliver only on `invoice.paid` (or `getInvoice(...)['status'] === 'paid'`).
3. Match the invoice to your order: your `orderId` or `metadata`, and the same amount and currency as the order's current total.
4. Ignore test events (`Webhook::isTestEvent()`), and in your live shop ignore invoices with `'test' => true`.
5. Handle each event `id` once, and answer `2xx` quickly.
6. Do not compare crypto amounts yourself. ArionPay decides when an invoice is paid, including payments inside your store's payment tolerance and payments you accept in Payment Radar.

## Test without real money

```php
$invoice = $arionpay->createInvoice(['amount' => '10', 'orderId' => 'test-1', 'asset' => 'USDT_TRC20', 'test' => true]);
$arionpay->simulatePayment($invoice['id'], 'exact'); // your webhook gets invoice.paid, like a real payment
```

Scenarios: `exact`, `detected`, `confirm`, `underpaid_1pct`, `underpaid_5pct`, `overpaid`, `partial_half`, `late`.

`$arionpay->sendTestWebhook('invoice.paid')` sends a signed sample event to your store's webhook address. It describes a made-up invoice (`inv_test_...`) and must never change an order.

## Reference

| Method | Returns |
| --- | --- |
| `createInvoice(array $params)` | `id`, `invoiceUrl`, `status`, `amountFiat`, `currency`, `asset`, `address`, `amountCrypto`, `expiresAt`, `orderId` |
| `getInvoice(string $id)` | The invoice, with the webhook field names (`status`, `amountFiat`, `currency`, `asset`, `paidCrypto`, `transactions`, `test`, `metadata`, ...). |
| `simulatePayment(string $id, string $scenario)` | Sandbox only (test invoices). |
| `sendTestWebhook(string $type = 'invoice.paid')` | `delivered`, `httpStatus`, `eventId` |
| `currencies()` | Coins you can pass as `asset` / `allowedAssets`. |
| `rates(string $currency = 'USD')` | Current coin prices. |
| `Webhook::verify($rawBody, $header, $secret)` / `Webhook::fromGlobals($secret)` | The event array, or throws `SignatureException`. |

`createInvoice` fields: `amount` (required), `currency` (default `USD`), `orderId`, `description`, `customerEmail`, `successUrl`, `cancelUrl`, `callbackUrl`, `asset`, `allowedAssets`, `expiresMin` (5 to 1440), `metadata`, `idempotencyKey`, `test`.

Errors are `ArionPay\ApiException` with `getStatus()` (HTTP status, `0` when ArionPay could not be reached), `getApiCode()` (for example `idempotency_key_reused`, `rate_limited`, `unknown_asset`) and `getMessage()`. Messages never contain your secret.

Options (third constructor argument): `webhookSecret`, `baseUrl` (default `https://merchant.arionpay.com`), `timeout` (seconds, default 20), `maxAttempts` (default 3), `http` (`auto` or `streams`), `appInfo`.

## License

MIT
