<?php
declare(strict_types=1);

@date_default_timezone_set(@date_default_timezone_get() ?: 'UTC');

function bvsw_now(): string
{
    return date('Y-m-d H:i:s');
}

function bvsw_log(string $event, array $data = []): void
{
    $line = '[' . bvsw_now() . '] ' . $event . ' ' . json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    $targets = [
        __DIR__ . '/stripe_refund_webhook.log',
        dirname(__DIR__) . '/stripe_refund_webhook.log',
        __DIR__ . '/private_html/stripe_refund_webhook.log',
    ];

    foreach ($targets as $file) {
        $dir = dirname($file);
        if (is_dir($dir) || @mkdir($dir, 0775, true)) {
            @file_put_contents($file, $line, FILE_APPEND);
            break;
        }
    }
}

function bvsw_require_if_exists(string $path): void
{
    if (is_file($path)) {
        require_once $path;
    }
}

bvsw_require_if_exists(__DIR__ . '/includes/order_refund.php');
bvsw_require_if_exists(dirname(__DIR__) . '/order_refund.php');
bvsw_require_if_exists(__DIR__ . '/includes/stripe_refund_engine.php');
bvsw_require_if_exists(__DIR__ . '/includes/db.php');
bvsw_require_if_exists(dirname(__DIR__) . '/db.php');

function bvsw_db()
{
    foreach (['pdo', 'PDO', 'db', 'conn', 'mysqli'] as $k) {
        if (!array_key_exists($k, $GLOBALS)) {
            continue;
        }
        $db = $GLOBALS[$k];
        if ($db instanceof PDO || $db instanceof mysqli) {
            return $db;
        }
    }
    throw new RuntimeException('DB connection unavailable for Stripe refund webhook.');
}

function bvsw_is_pdo($db): bool
{
    return $db instanceof PDO;
}

function bvsw_query_all(string $sql, array $params = []): array
{
    $db = bvsw_db();

    if (bvsw_is_pdo($db)) {
        $stmt = $db->prepare($sql);
        if (!$stmt) {
            throw new RuntimeException('PDO prepare failed.');
        }
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return is_array($rows) ? $rows : [];
    }

    if ($params !== []) {
        foreach ($params as $k => $v) {
            $sql = str_replace(':' . $k, '?', $sql);
        }
    }

    $stmt = $db->prepare($sql);
    if (!$stmt) {
        throw new RuntimeException('mysqli prepare failed: ' . $db->error);
    }

    if ($params !== []) {
        $ordered = array_values($params);
        $types = str_repeat('s', count($ordered));
        $stmt->bind_param($types, ...$ordered);
    }

    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();
        throw new RuntimeException('mysqli execute failed: ' . $error);
    }

    $result = $stmt->get_result();
    if (!$result) {
        $stmt->close();
        return [];
    }
    $rows = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return is_array($rows) ? $rows : [];
}

function bvsw_query_one(string $sql, array $params = []): ?array
{
    $rows = bvsw_query_all($sql, $params);
    return $rows[0] ?? null;
}

function bvsw_exec(string $sql, array $params = []): int
{
    $db = bvsw_db();

    if (bvsw_is_pdo($db)) {
        $stmt = $db->prepare($sql);
        if (!$stmt) {
            throw new RuntimeException('PDO prepare failed.');
        }
        $stmt->execute($params);
        return (int)$stmt->rowCount();
    }

    if ($params !== []) {
        foreach ($params as $k => $v) {
            $sql = str_replace(':' . $k, '?', $sql);
        }
    }

    $stmt = $db->prepare($sql);
    if (!$stmt) {
        throw new RuntimeException('mysqli prepare failed: ' . $db->error);
    }

    if ($params !== []) {
        $ordered = array_values($params);
        $types = str_repeat('s', count($ordered));
        $stmt->bind_param($types, ...$ordered);
    }

    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();
        throw new RuntimeException('mysqli execute failed: ' . $error);
    }

    $affected = (int)$stmt->affected_rows;
    $stmt->close();
    return $affected;
}

function bvsw_columns(string $table): array
{
    static $cache = [];
    if (isset($cache[$table])) {
        return $cache[$table];
    }

    $columns = [];
    try {
        $rows = bvsw_query_all('SHOW COLUMNS FROM `' . str_replace('`', '', $table) . '`');
        foreach ($rows as $row) {
            $f = (string)($row['Field'] ?? '');
            if ($f !== '') {
                $columns[$f] = true;
            }
        }
    } catch (Throwable $e) {
        $columns = [];
    }

    $cache[$table] = $columns;
    return $columns;
}

function bvsw_has_column(string $table, string $column): bool
{
    $columns = bvsw_columns($table);
    return isset($columns[$column]);
}

function bvsw_table_exists(string $table): bool
{
    static $cache = [];
    if (array_key_exists($table, $cache)) {
        return $cache[$table];
    }

    $row = bvsw_query_one('SHOW TABLES LIKE :name', ['name' => $table]);
    $cache[$table] = is_array($row) && $row !== [];
    return $cache[$table];
}

function bvsw_env(string $key): string
{
    $value = getenv($key);
    return is_string($value) ? trim($value) : '';
}

function bvsw_webhook_secret(): string
{
    $candidates = [
        bvsw_env('STRIPE_REFUND_WEBHOOK_SECRET'),
        bvsw_env('STRIPE_WEBHOOK_SECRET'),
        (string)($GLOBALS['stripe_refund_webhook_secret'] ?? ''),
        (string)($GLOBALS['stripe_webhook_secret'] ?? ''),
        (string)($GLOBALS['config']['stripe_refund_webhook_secret'] ?? ''),
        (string)($GLOBALS['config']['stripe_webhook_secret'] ?? ''),
    ];

    foreach ($candidates as $c) {
        $c = trim((string)$c);
        if ($c !== '') {
            return $c;
        }
    }
    return '';
}

function bvsw_parse_signature_header(string $header): array
{
    $out = ['t' => '', 'v1' => []];
    foreach (explode(',', $header) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$k, $v] = explode('=', $part, 2);
        $k = trim($k);
        $v = trim($v);
        if ($k === 't') {
            $out['t'] = $v;
        } elseif ($k === 'v1') {
            $out['v1'][] = $v;
        }
    }
    return $out;
}

function bvsw_verify_signature(string $payload, string $header, string $secret): bool
{
    if ($payload === '' || $header === '' || $secret === '') {
        return false;
    }

    $parsed = bvsw_parse_signature_header($header);
    $t = $parsed['t'];
    $v1s = $parsed['v1'];
    if ($t === '' || $v1s === []) {
        return false;
    }

    if (!ctype_digit((string)$t)) {
        return false;
    }

    if (abs(time() - (int)$t) > 300) {
        return false;
    }

    $signed = $t . '.' . $payload;
    $expected = hash_hmac('sha256', $signed, $secret);
    foreach ($v1s as $sig) {
        if (is_string($sig) && hash_equals($expected, $sig)) {
            return true;
        }
    }

    return false;
}

function bvsw_json_response(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

function bvsw_event_already_handled(string $eventId): bool
{
    if ($eventId === '') {
        return false;
    }

    if (!bvsw_table_exists('webhook_events')) {
        return false;
    }

    $where = [];
    $params = ['event_id' => $eventId];
    if (bvsw_has_column('webhook_events', 'event_id')) {
        $where[] = 'event_id = :event_id';
    } elseif (bvsw_has_column('webhook_events', 'provider_event_id')) {
        $where[] = 'provider_event_id = :event_id';
    }

    if ($where === []) {
        return false;
    }

    if (bvsw_has_column('webhook_events', 'provider')) {
        $where[] = 'provider = :provider';
        $params['provider'] = 'stripe';
    }

    $row = bvsw_query_one('SELECT 1 FROM webhook_events WHERE ' . implode(' AND ', $where) . ' LIMIT 1', $params);
    return $row !== null;
}

function bvsw_record_event(string $eventId, string $eventType, string $payloadJson): void
{
    if ($eventId === '' || !bvsw_table_exists('webhook_events')) {
        return;
    }

    $cols = bvsw_columns('webhook_events');
    if ($cols === []) {
        return;
    }

    $fields = [];
    $holders = [];
    $params = [];

    $map = [
        'provider' => 'stripe',
        'event_id' => $eventId,
        'provider_event_id' => $eventId,
        'event_type' => $eventType,
        'payload' => $payloadJson,
        'payload_json' => $payloadJson,
        'status' => 'processed',
        'created_at' => bvsw_now(),
        'updated_at' => bvsw_now(),
    ];

    foreach ($map as $k => $v) {
        if (!isset($cols[$k])) {
            continue;
        }
        $fields[] = '`' . $k . '`';
        $holders[] = ':' . $k;
        $params[$k] = $v;
    }

    if ($fields === []) {
        return;
    }

    try {
        bvsw_exec('INSERT INTO webhook_events (' . implode(',', $fields) . ') VALUES (' . implode(',', $holders) . ')', $params);
    } catch (Throwable $e) {
        bvsw_log('webhook_event_insert_failed', ['event_id' => $eventId, 'error' => $e->getMessage()]);
    }
}

function bvsw_minor_to_major($amount): float
{
    return round(((float)$amount) / 100, 2);
}

function bvsw_normalize_refund_status(string $status): string
{
    $status = strtolower(trim($status));
    if (function_exists('bv_stripe_refund_normalize_status')) {
        try {
            $n = (string)bv_stripe_refund_normalize_status($status);
            if ($n !== '') {
                return strtolower($n);
            }
        } catch (Throwable $e) {
        }
    }

    if (in_array($status, ['succeeded', 'success', 'completed'], true)) {
        return 'succeeded';
    }
    if (in_array($status, ['failed', 'canceled', 'cancelled'], true)) {
        return $status === 'failed' ? 'failed' : 'cancelled';
    }
    if (in_array($status, ['pending', 'requires_action'], true)) {
        return 'pending';
    }
    return $status !== '' ? $status : 'pending';
}

function bvsw_extract_refunds(array $event): array
{
    $type = (string)($event['type'] ?? '');
    $object = $event['data']['object'] ?? [];
    if (!is_array($object)) {
        return [];
    }

    if (in_array($type, ['refund.updated', 'refund.created', 'refund.failed', 'charge.refund.updated'], true)) {
        return [$object];
    }

    if ($type === 'charge.refunded') {
        $refunds = $object['refunds']['data'] ?? [];
        if (is_array($refunds) && $refunds !== []) {
            return array_values(array_filter($refunds, static fn($r) => is_array($r)));
        }
    }

    return [];
}

function bvsw_find_refund_by_provider_refund_id(string $providerRefundId): ?array
{
    if ($providerRefundId === '' || !bvsw_table_exists('order_refund_transactions')) {
        return null;
    }

    $row = bvsw_query_one(
        'SELECT rt.refund_id FROM order_refund_transactions rt WHERE rt.provider_refund_id = :rid ORDER BY rt.id DESC LIMIT 1',
        ['rid' => $providerRefundId]
    );

    $refundId = (int)($row['refund_id'] ?? 0);
    if ($refundId <= 0) {
        return null;
    }

    if (function_exists('bv_order_refund_get_by_id')) {
        return bv_order_refund_get_by_id($refundId);
    }

    return bvsw_query_one('SELECT * FROM order_refunds WHERE id = :id LIMIT 1', ['id' => $refundId]);
}

function bvsw_find_refund_from_payload(array $refundObj): ?array
{
    $metaRefundId = (int)($refundObj['metadata']['refund_id'] ?? 0);
    if ($metaRefundId > 0) {
        if (function_exists('bv_order_refund_get_by_id')) {
            $r = bv_order_refund_get_by_id($metaRefundId);
            if ($r) {
                return $r;
            }
        }

        if (bvsw_table_exists('order_refunds')) {
            $r = bvsw_query_one('SELECT * FROM order_refunds WHERE id = :id LIMIT 1', ['id' => $metaRefundId]);
            if ($r) {
                return $r;
            }
        }
    }

    $providerRefundId = trim((string)($refundObj['id'] ?? ''));
    if ($providerRefundId !== '') {
        $r = bvsw_find_refund_by_provider_refund_id($providerRefundId);
        if ($r) {
            return $r;
        }

        if (bvsw_table_exists('order_refunds') && bvsw_has_column('order_refunds', 'payment_reference_snapshot')) {
            $r = bvsw_query_one('SELECT * FROM order_refunds WHERE payment_reference_snapshot = :ref ORDER BY id DESC LIMIT 1', ['ref' => $providerRefundId]);
            if ($r) {
                return $r;
            }
        }
    }

    $paymentIntent = trim((string)($refundObj['payment_intent'] ?? ''));
    $chargeId = trim((string)($refundObj['charge'] ?? ''));
    if ($paymentIntent !== '' && bvsw_table_exists('order_refund_transactions')) {
        $r = bvsw_query_one(
            'SELECT r.*
             FROM order_refund_transactions rt
             INNER JOIN order_refunds r ON r.id = rt.refund_id
             WHERE rt.provider_payment_intent_id = :pi
             ORDER BY rt.id DESC
             LIMIT 1',
            ['pi' => $paymentIntent]
        );
        if ($r) {
            return $r;
        }
    }

    if ($chargeId !== '' && bvsw_table_exists('order_refunds') && bvsw_has_column('order_refunds', 'payment_reference_snapshot')) {
        $r = bvsw_query_one(
            'SELECT * FROM order_refunds WHERE payment_reference_snapshot LIKE :charge ORDER BY id DESC LIMIT 1',
            ['charge' => '%' . $chargeId . '%']
        );
        if ($r) {
            return $r;
        }
    }

    return null;
}


function bvsw_is_refund_header_finalized(array $refund): bool
{
    $status = strtolower(trim((string)($refund['status'] ?? '')));
    $refundedAt = trim((string)($refund['refunded_at'] ?? ''));

    if (in_array($status, ['refunded', 'partially_refunded'], true) || $refundedAt !== '') {
        return true;
    }

    $refundId = (int)($refund['id'] ?? 0);
    if ($refundId <= 0 || !bvsw_table_exists('order_refunds')) {
        return false;
    }

    $fresh = bvsw_query_one('SELECT status, refunded_at FROM order_refunds WHERE id = :id LIMIT 1', ['id' => $refundId]);
    if (!$fresh) {
        return false;
    }

    $freshStatus = strtolower(trim((string)($fresh['status'] ?? '')));
    $freshRefundedAt = trim((string)($fresh['refunded_at'] ?? ''));
    return in_array($freshStatus, ['refunded', 'partially_refunded'], true) || $freshRefundedAt !== '';
}

function bvsw_transaction_exists(int $refundId, string $status, string $providerRefundId): bool
{
    if ($refundId <= 0 || $status === '' || !bvsw_table_exists('order_refund_transactions')) {
        return false;
    }

    $params = ['rid' => $refundId, 'status' => $status];
    $sql = 'SELECT 1 FROM order_refund_transactions WHERE refund_id = :rid AND transaction_status = :status';

    if ($providerRefundId !== '' && bvsw_has_column('order_refund_transactions', 'provider_refund_id')) {
        $sql .= ' AND provider_refund_id = :provider_refund_id';
        $params['provider_refund_id'] = $providerRefundId;
    }

    $sql .= ' ORDER BY id DESC LIMIT 1';
    return bvsw_query_one($sql, $params) !== null;
}

function bvsw_upsert_transaction(int $refundId, string $status, array $refundObj): void
{
    $providerRefundId = trim((string)($refundObj['id'] ?? ''));
	   if (bvsw_transaction_exists($refundId, $status, $providerRefundId)) {
        return;
    }

    $paymentIntent = trim((string)($refundObj['payment_intent'] ?? ''));
    $currency = strtoupper(trim((string)($refundObj['currency'] ?? 'USD')));
    $amount = bvsw_minor_to_major($refundObj['amount'] ?? 0);
    $payload = json_encode($refundObj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($payload)) {
        $payload = '{}';
    }

    if (function_exists('bv_order_refund_insert_transaction')) {
        try {
            bv_order_refund_insert_transaction([
                'refund_id' => $refundId,
                'transaction_type' => 'provider_refund_webhook',
                'transaction_status' => $status,
                'provider' => 'stripe',
                'provider_refund_id' => $providerRefundId,
                'provider_payment_intent_id' => $paymentIntent,
                'currency' => $currency,
                'amount' => $amount,
                'raw_response_payload' => $payload,
                'created_at' => bvsw_now(),
            ]);
            return;
        } catch (Throwable $e) {
            bvsw_log('insert_transaction_helper_failed', ['refund_id' => $refundId, 'error' => $e->getMessage()]);
        }
    }

    if (!bvsw_table_exists('order_refund_transactions')) {
        return;
    }

    $fields = ['refund_id', 'transaction_type', 'transaction_status', 'provider', 'provider_refund_id', 'provider_payment_intent_id', 'currency', 'amount', 'created_at'];
    $params = [
        'refund_id' => $refundId,
        'transaction_type' => 'provider_refund_webhook',
        'transaction_status' => $status,
        'provider' => 'stripe',
        'provider_refund_id' => $providerRefundId,
        'provider_payment_intent_id' => $paymentIntent,
        'currency' => $currency,
        'amount' => $amount,
        'created_at' => bvsw_now(),
    ];

    if (bvsw_has_column('order_refund_transactions', 'raw_response_payload')) {
        $fields[] = 'raw_response_payload';
        $params['raw_response_payload'] = $payload;
    }
    if (bvsw_has_column('order_refund_transactions', 'processed_at')) {
        $fields[] = 'processed_at';
        $params['processed_at'] = bvsw_now();
    }
    if (bvsw_has_column('order_refund_transactions', 'updated_at')) {
        $fields[] = 'updated_at';
        $params['updated_at'] = bvsw_now();
    }

    $colSql = implode(',', array_map(static fn($f) => '`' . $f . '`', $fields));
    $valSql = implode(',', array_map(static fn($f) => ':' . $f, $fields));
    bvsw_exec('INSERT INTO order_refund_transactions (' . $colSql . ') VALUES (' . $valSql . ')', $params);
}

function bvsw_upsert_ledger(array $refund, string $status, float $amount, string $providerRefundId): void
{
    $refundId = (int)($refund['id'] ?? 0);
    $orderId = (int)($refund['order_id'] ?? 0);
    if ($refundId <= 0 || !bvsw_table_exists('order_financial_ledger')) {
        return;
    }

    $entryType = $status === 'succeeded' ? 'refund_out' : 'refund_adjustment';
    $note = $status === 'succeeded' ? 'Stripe refund completed via webhook' : 'Stripe refund ' . $status . ' via webhook';

    if ($status === 'succeeded' && $providerRefundId !== '' && bvsw_has_column('order_financial_ledger', 'provider_reference')) {
        $existing = bvsw_query_one(
            'SELECT id FROM order_financial_ledger WHERE refund_id = :rid AND provider_reference = :pref AND entry_type = :entry_type LIMIT 1',
            ['rid' => $refundId, 'pref' => $providerRefundId, 'entry_type' => $entryType]
        );
        if ($existing) {
            return;
        }
    }

    if (function_exists('bv_order_refund_insert_ledger')) {
        try {
            bv_order_refund_insert_ledger([
                'order_id' => $orderId,
                'refund_id' => $refundId,
                'event_type' => $status === 'succeeded' ? 'refund_refunded' : 'refund_failed',
                'amount' => $amount,
                'currency' => (string)($refund['currency'] ?? 'USD'),
                'provider' => 'stripe',
                'provider_reference' => $providerRefundId,
                'note' => $note,
                'created_at' => bvsw_now(),
            ]);
            return;
        } catch (Throwable $e) {
            bvsw_log('insert_ledger_helper_failed', ['refund_id' => $refundId, 'error' => $e->getMessage()]);
        }
    }

    $fields = ['order_id', 'refund_id', 'entry_type', 'direction', 'currency', 'amount', 'reference_type', 'reference_id', 'memo', 'entry_status', 'created_at'];
    $params = [
        'order_id' => $orderId,
        'refund_id' => $refundId,
        'entry_type' => $entryType,
        'direction' => 'out',
        'currency' => (string)($refund['currency'] ?? 'USD'),
        'amount' => $amount,
        'reference_type' => 'stripe_refund',
        'reference_id' => $providerRefundId !== '' ? $providerRefundId : (string)$refundId,
        'memo' => $note,
        'entry_status' => $status === 'succeeded' ? 'posted' : 'failed',
        'created_at' => bvsw_now(),
    ];

    if (bvsw_has_column('order_financial_ledger', 'provider')) {
        $fields[] = 'provider';
        $params['provider'] = 'stripe';
    }
    if (bvsw_has_column('order_financial_ledger', 'provider_reference')) {
        $fields[] = 'provider_reference';
        $params['provider_reference'] = $providerRefundId;
    }
    if (bvsw_has_column('order_financial_ledger', 'updated_at')) {
        $fields[] = 'updated_at';
        $params['updated_at'] = bvsw_now();
    }

    $colSql = implode(',', array_map(static fn($f) => '`' . $f . '`', $fields));
    $valSql = implode(',', array_map(static fn($f) => ':' . $f, $fields));
    bvsw_exec('INSERT INTO order_financial_ledger (' . $colSql . ') VALUES (' . $valSql . ')', $params);
}

function bvsw_sync_order_payment_status(int $orderId, string $paymentStatus): void
{
    if ($orderId <= 0 || !bvsw_table_exists('orders') || !bvsw_has_column('orders', 'payment_status')) {
        return;
    }

    bvsw_exec(
        'UPDATE orders SET payment_status = :payment_status' . (bvsw_has_column('orders', 'updated_at') ? ', updated_at = :updated_at' : '') . ' WHERE id = :id LIMIT 1',
        bvsw_has_column('orders', 'updated_at')
            ? ['payment_status' => $paymentStatus, 'updated_at' => bvsw_now(), 'id' => $orderId]
            : ['payment_status' => $paymentStatus, 'id' => $orderId]
    );
}

function bvsw_process_refund(array $refundObj): void
{
    $providerRefundId = trim((string)($refundObj['id'] ?? ''));
    $status = bvsw_normalize_refund_status((string)($refundObj['status'] ?? 'pending'));

    $refund = bvsw_find_refund_from_payload($refundObj);
    if (!$refund) {
        bvsw_log('refund_mapping_not_found', ['provider_refund_id' => $providerRefundId]);
        throw new RuntimeException('refund_mapping_not_found');
    }

    $refundId = (int)($refund['id'] ?? 0);
    if ($refundId <= 0) {
        throw new RuntimeException('invalid_refund_id');
    }

    $amount = bvsw_minor_to_major($refundObj['amount'] ?? 0);
    if ($amount <= 0) {
        $amount = (float)($refund['actual_refunded_amount'] ?? 0);
        if ($amount <= 0) {
            $amount = (float)($refund['approved_refund_amount'] ?? 0);
        }
    }
    $amount = round(max(0.0, $amount), 2);

    if ($status === 'succeeded') {
        // Re-read refund with a fresh DB query to get the current persisted status
        // before making any writes. This prevents race conditions between concurrent
        // webhook deliveries of the same event.
        $freshRefund = bvsw_table_exists('order_refunds')
            ? bvsw_query_one('SELECT * FROM order_refunds WHERE id = :id LIMIT 1', ['id' => $refundId])
            : null;
        if ($freshRefund) {
            $refund = $freshRefund;
        }

        $refundHeaderFinalized = bvsw_is_refund_header_finalized($refund);

        // Always upsert the transaction record (bvsw_upsert_transaction has its own
        // dedup guard based on provider_refund_id + status).
        bvsw_upsert_transaction($refundId, 'succeeded', $refundObj);

        if ($refundHeaderFinalized) {
            // Header already finalized — write the ledger only if this exact
            // provider_refund_id + entry_type combo is not already there (the
            // bvsw_upsert_ledger function already performs this check).
            bvsw_upsert_ledger($refund, 'succeeded', $amount, $providerRefundId);
            bvsw_log('refund_already_finalized_skip_duplicate_finalization', ['refund_id' => $refundId, 'provider_refund_id' => $providerRefundId]);
            return;
        }

        // Only write the ledger entry when we are actually going to finalize
        // the refund header, preventing a ledger row on replay before header update.
        bvsw_upsert_ledger($refund, 'succeeded', $amount, $providerRefundId);

        if (function_exists('bv_order_refund_mark_refunded')) {
            try {
                bv_order_refund_mark_refunded($refundId, $amount, [
                    'provider' => 'stripe',
                    'provider_refund_id' => $providerRefundId,
                    'provider_payment_intent_id' => (string)($refundObj['payment_intent'] ?? ''),
                    'amount' => $amount,
                    'currency' => strtoupper((string)($refundObj['currency'] ?? ($refund['currency'] ?? 'USD'))),
                    'status' => 'succeeded',
                    'raw_response_payload' => $refundObj,
                 ], 0, 'Stripe webhook succeeded', 'system');
            } catch (Throwable $e) {
                bvsw_log('mark_refunded_helper_failed', ['refund_id' => $refundId, 'error' => $e->getMessage()]);
                throw new RuntimeException('mark_refunded_helper_failed: ' . $e->getMessage(), 0, $e);
            }
        } else {
            bvsw_exec(
                'UPDATE order_refunds SET status = :status, actual_refunded_amount = :amount, refunded_at = :refunded_at, updated_at = :updated_at WHERE id = :id LIMIT 1',
                ['status' => 'refunded', 'amount' => $amount, 'refunded_at' => bvsw_now(), 'updated_at' => bvsw_now(), 'id' => $refundId]
            );
        }

       if (function_exists('bv_order_refund_sync_cancellation_bridge')) {
            try {
                bv_order_refund_sync_cancellation_bridge($refundId);
            } catch (Throwable $e) {
                bvsw_log('sync_cancellation_failed', ['refund_id' => $refundId, 'error' => $e->getMessage()]);
                throw new RuntimeException('sync_cancellation_failed: ' . $e->getMessage(), 0, $e);
            }
        }

        if (function_exists('bv_order_refund_sync_order_payment_status')) {
            try {
                bv_order_refund_sync_order_payment_status($refundId);
            } catch (Throwable $e) {
                bvsw_log('sync_order_status_helper_failed', ['refund_id' => $refundId, 'error' => $e->getMessage()]);
                throw new RuntimeException('sync_order_status_helper_failed: ' . $e->getMessage(), 0, $e);
            }
        } else {
            $approvedAmount = round((float)($refund['approved_refund_amount'] ?? 0), 2);
            $orderPaymentStatus = ($approvedAmount > 0 && $amount + 0.0001 < $approvedAmount) ? 'partially_refunded' : 'refunded';
            bvsw_sync_order_payment_status((int)($refund['order_id'] ?? 0), $orderPaymentStatus);
        }

        return;
    }

    if (in_array($status, ['failed', 'cancelled'], true)) {
        if (function_exists('bv_order_refund_mark_failed')) {
            try {
                bv_order_refund_mark_failed($refundId, 'Stripe webhook ' . $status, [
                    'provider' => 'stripe',
                    'provider_refund_id' => $providerRefundId,
                    'provider_payment_intent_id' => (string)($refundObj['payment_intent'] ?? ''),
                    'status' => $status,
                    'error_message' => (string)($refundObj['failure_reason'] ?? ''),
                    'raw_response_payload' => $refundObj,
                 ], 0, 'system');
            } catch (Throwable $e) {
                bvsw_log('mark_failed_helper_failed', ['refund_id' => $refundId, 'error' => $e->getMessage()]);
                throw new RuntimeException('mark_failed_helper_failed: ' . $e->getMessage(), 0, $e);
            }
        } else {
            bvsw_exec(
                'UPDATE order_refunds SET status = :status, failed_at = :failed_at, updated_at = :updated_at WHERE id = :id LIMIT 1',
                ['status' => $status, 'failed_at' => bvsw_now(), 'updated_at' => bvsw_now(), 'id' => $refundId]
            );
        }

        bvsw_upsert_transaction($refundId, $status, $refundObj);
        bvsw_upsert_ledger($refund, $status, $amount, $providerRefundId);
        return;
    }

    if ($status === 'pending' || $status === 'requires_action') {
        $currentStatus = strtolower((string)($refund['status'] ?? ''));
        if ($currentStatus === 'approved' && function_exists('bv_order_refund_mark_processing')) {
            try {
                bv_order_refund_mark_processing($refundId, 0, 'Stripe webhook pending', 'system');
            } catch (Throwable $e) {
                bvsw_log('mark_processing_helper_failed', ['refund_id' => $refundId, 'error' => $e->getMessage()]);
                throw new RuntimeException('mark_processing_helper_failed: ' . $e->getMessage(), 0, $e);
            }
        }
        bvsw_upsert_transaction($refundId, 'pending', $refundObj); 
    }
}

$payload = (string)file_get_contents('php://input');
$signatureHeader = (string)($_SERVER['HTTP_STRIPE_SIGNATURE'] ?? $_SERVER['Stripe-Signature'] ?? '');
$secret = bvsw_webhook_secret();

if ($secret === '') {
    bvsw_log('missing_webhook_secret');
    bvsw_json_response(500, ['ok' => false, 'error' => 'webhook_secret_missing']);
    exit;
}

if (!bvsw_verify_signature($payload, $signatureHeader, $secret)) {
    bvsw_log('invalid_signature', ['has_header' => $signatureHeader !== '' ? 1 : 0]);
    bvsw_json_response(400, ['ok' => false, 'error' => 'invalid_signature']);
    exit;
}

$event = json_decode($payload, true);
if (!is_array($event)) {
    bvsw_json_response(400, ['ok' => false, 'error' => 'invalid_json']);
    exit;
}

$eventId = trim((string)($event['id'] ?? ''));
$eventType = trim((string)($event['type'] ?? ''));

try {
    if ($eventId !== '' && bvsw_event_already_handled($eventId)) {
        bvsw_json_response(200, ['ok' => true, 'duplicate' => true]);
        exit;
    }

    $refundObjects = bvsw_extract_refunds($event);
    if ($refundObjects === []) {
        bvsw_record_event($eventId, $eventType, $payload);
        bvsw_json_response(200, ['ok' => true, 'ignored' => true]);
        exit;
    }

    foreach ($refundObjects as $refundObj) {
        try {
            bvsw_process_refund($refundObj);
        } catch (Throwable $e) {
            bvsw_log('process_refund_failed', [
                'event_id' => $eventId,
                'event_type' => $eventType,
              'refund_id' => (string)($refundObj['id'] ?? ''),
                'error' => $e->getMessage(),
            ]);
            throw $e;
        }
    }

    bvsw_record_event($eventId, $eventType, $payload);
    bvsw_json_response(200, ['ok' => true]);
} catch (Throwable $e) {
    bvsw_log('webhook_exception', ['event_id' => $eventId, 'error' => $e->getMessage()]);
    bvsw_json_response(500, ['ok' => false, 'error' => 'refund_processing_failed']);
}