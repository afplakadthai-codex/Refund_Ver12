<?php
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

require_once dirname(__DIR__) . '/includes/order_refund.php';

function bvsrv_h($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function bvsrv_current_seller_id(): int
{
    foreach (['seller_id', 'user_id', 'member_id', 'id'] as $k) {
        if (isset($_SESSION[$k]) && is_numeric($_SESSION[$k]) && (int)$_SESSION[$k] > 0) {
            return (int)$_SESSION[$k];
        }
    }
    return function_exists('bv_order_refund_current_user_id') ? (int)bv_order_refund_current_user_id() : 0;
}

function bvsrv_csrf_token(): string
{
    $token = $_SESSION['_csrf_seller_refunds']['refund_actions'] ?? '';
    if (!is_string($token) || trim($token) === '') {
        $token = bin2hex(random_bytes(16));
        $_SESSION['_csrf_seller_refunds']['refund_actions'] = $token;
    }
    return $token;
}

$sellerId = bvsrv_current_seller_id();
$refundId = (int)($_GET['id'] ?? 0);

if ($sellerId <= 0 || $refundId <= 0) {
    http_response_code(403);
    exit('Invalid access');
}

$refund = bv_order_refund_get_by_id($refundId);
if (!$refund) {
    http_response_code(404);
    exit('Refund not found');
}

$items = bv_order_refund_get_items_for_seller($refundId, $sellerId);
if ($items === []) {
    http_response_code(403);
    exit('No seller-owned refund items for this refund.');
}

$decision = bv_order_refund_get_seller_decision($refundId, $sellerId);
$requested = (float)($decision['requested_amount'] ?? 0);
$approved = (float)($decision['approved_amount'] ?? 0);
$status = (string)($decision['status'] ?? 'pending_approval');
$currency = (string)($refund['currency'] ?? 'USD');
$csrf = bvsrv_csrf_token();
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Seller Refund View</title>
    <style>
        body{font-family:Arial,sans-serif;background:#f4f6fb;margin:0;padding:24px;color:#1f2937}
        .container{max-width:960px;margin:0 auto}
        .card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin-bottom:12px}
        table{width:100%;border-collapse:collapse}
        th,td{border-bottom:1px solid #eef2f7;padding:8px;text-align:left}
        .actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
        .btn{padding:9px 12px;border-radius:8px;border:0;cursor:pointer;font-weight:700}
        .approve{background:#16a34a;color:#fff}
        .reject{background:#dc2626;color:#fff}
        .muted{color:#6b7280}
        textarea,input[type=number]{padding:8px;border:1px solid #d1d5db;border-radius:8px;width:100%}
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <h2>Refund #<?php echo bvsrv_h($refundId); ?> (Seller Slice)</h2>
        <div class="muted">Header status: <?php echo bvsrv_h((string)($refund['status'] ?? '')); ?></div>
        <div class="muted">Seller decision status: <?php echo bvsrv_h($status); ?></div>
        <div class="muted">Requested: <?php echo bvsrv_h(number_format($requested, 2) . ' ' . $currency); ?></div>
        <div class="muted">Approved: <?php echo bvsrv_h(number_format($approved, 2) . ' ' . $currency); ?></div>
    </div>

    <div class="card">
        <h3>Seller-owned refund items</h3>
        <table>
            <thead><tr><th>Item ID</th><th>Listing</th><th>Requested</th><th>Approved</th></tr></thead>
            <tbody>
            <?php foreach ($items as $item): ?>
                <tr>
                    <td><?php echo bvsrv_h((int)$item['id']); ?></td>
                    <td><?php echo bvsrv_h((string)($item['listing_title'] ?? 'Listing')); ?></td>
                    <td><?php echo bvsrv_h(number_format((float)($item['requested_refund_amount'] ?? 0), 2)); ?></td>
                    <td><?php echo bvsrv_h(number_format((float)($item['approved_refund_amount'] ?? 0), 2)); ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php if ($status === 'pending_approval'): ?>
    <div class="card">
        <form method="post" action="/seller/refund_action.php">
            <input type="hidden" name="csrf_token" value="<?php echo bvsrv_h($csrf); ?>">
            <input type="hidden" name="refund_id" value="<?php echo bvsrv_h($refundId); ?>">
            <input type="hidden" name="return_url" value="<?php echo bvsrv_h('/seller/refund_view.php?id=' . $refundId); ?>">
            <label>Approved Amount (your seller slice)</label>
            <input type="number" step="0.01" min="0" name="approved_refund_amount" value="<?php echo bvsrv_h(number_format($requested, 2, '.', '')); ?>">
            <label>Note</label>
            <textarea name="note" rows="3" placeholder="Optional decision note"></textarea>
            <div class="actions" style="margin-top:10px;">
                <button class="btn approve" type="submit" name="action" value="approve">Approve Seller Slice</button>
                <button class="btn reject" type="submit" name="action" value="reject">Reject Seller Slice</button>
            </div>
        </form>
    </div>
    <?php endif; ?>
</div>
</body>
</html>
