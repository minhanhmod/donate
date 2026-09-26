-- MinhAnhMod Donate PostgreSQL schema
-- server.js also creates these tables automatically on startup.

CREATE TABLE IF NOT EXISTS payment_orders (
  id BIGSERIAL PRIMARY KEY,
  order_code BIGINT UNIQUE NOT NULL,
  amount BIGINT NOT NULL CHECK (amount > 0),
  donor_name VARCHAR(40) NOT NULL DEFAULT 'Ẩn danh',
  donor_message VARCHAR(500) NOT NULL DEFAULT '',
  status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
  checkout_url TEXT,
  reference VARCHAR(120),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  paid_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_orders_status_paid_at
  ON payment_orders(status, paid_at DESC);

CREATE TABLE IF NOT EXISTS chat_messages (
  id UUID PRIMARY KEY,
  name VARCHAR(30) NOT NULL,
  message VARCHAR(500) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at
  ON chat_messages(created_at DESC);
