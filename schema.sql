CREATE TABLE IF NOT EXISTS app_state (
  key text PRIMARY KEY,
  value jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tickets (
  id text PRIMARY KEY,
  kind text NOT NULL,
  username text NOT NULL,
  display_name text NOT NULL,
  department text NOT NULL DEFAULT '',
  factory text NOT NULL DEFAULT '',
  client_ip inet,
  primary_category text NOT NULL,
  sub_category text NOT NULL,
  description text NOT NULL,
  material text NOT NULL DEFAULT '',
  attachments jsonb NOT NULL DEFAULT '[]'::jsonb,
  assigned_to text NOT NULL DEFAULT 'Unassigned',
  status text NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','In progress','Resolved','Closed')),
  eta timestamptz,
  note text NOT NULL DEFAULT '',
  public_token_hash text,
  complaint_desk text NOT NULL DEFAULT 'it',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS public_token_hash text;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS complaint_desk text NOT NULL DEFAULT 'it';
CREATE INDEX IF NOT EXISTS tickets_created_at_idx ON tickets(created_at DESC);
CREATE INDEX IF NOT EXISTS tickets_username_idx ON tickets(username);
CREATE INDEX IF NOT EXISTS tickets_desk_idx ON tickets(complaint_desk);
CREATE TABLE IF NOT EXISTS ticket_events (
  id bigserial PRIMARY KEY,
  ticket_id text NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  actor text NOT NULL,
  event_type text NOT NULL,
  detail text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS login_attempts (
  client_ip inet PRIMARY KEY,
  failures integer NOT NULL DEFAULT 0,
  blocked_until timestamptz
);
CREATE TABLE IF NOT EXISTS recovery_attempts (
  client_ip inet NOT NULL,
  username_hash text NOT NULL,
  failures integer NOT NULL DEFAULT 0,
  blocked_until timestamptz,
  PRIMARY KEY (client_ip, username_hash)
);
CREATE TABLE IF NOT EXISTS user_sessions (
  sid text PRIMARY KEY,
  username text NOT NULL,
  auth_version integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  client_ip text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions(username);
CREATE TABLE IF NOT EXISTS visitor_passes (
  id text PRIMARY KEY,
  tracking_token_hash text NOT NULL DEFAULT '',
  factory text NOT NULL DEFAULT '',
  visitor_name text NOT NULL,
  phone text NOT NULL DEFAULT '',
  address text NOT NULL DEFAULT '',
  purpose text NOT NULL DEFAULT '',
  department text NOT NULL DEFAULT '',
  host_username text NOT NULL DEFAULT '',
  host_name text NOT NULL DEFAULT '',
  vehicle_no text NOT NULL DEFAULT '',
  pass_no text NOT NULL DEFAULT '',
  visitor_count integer NOT NULL DEFAULT 1,
  belongings text NOT NULL DEFAULT '',
  id_card_photo text NOT NULL DEFAULT '',
  selfie_photo text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Approved','Checked In','Checked Out','Rejected')),
  entered_by text NOT NULL DEFAULT 'Security Gate',
  approved_by text NOT NULL DEFAULT '',
  approved_at timestamptz,
  checked_in_at timestamptz,
  checked_out_at timestamptz,
  decision_note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS visitor_passes_created_idx ON visitor_passes(created_at DESC);
CREATE INDEX IF NOT EXISTS visitor_passes_dept_idx ON visitor_passes(department);
CREATE INDEX IF NOT EXISTS visitor_passes_factory_idx ON visitor_passes(factory);
CREATE INDEX IF NOT EXISTS visitor_passes_status_idx ON visitor_passes(status);

CREATE TABLE IF NOT EXISTS material_gate_passes (
  id text PRIMARY KEY,
  tracking_token_hash text NOT NULL DEFAULT '',
  direction text NOT NULL CHECK (direction IN ('IN','OUT')),
  factory text NOT NULL DEFAULT '',
  material_type text NOT NULL DEFAULT '',
  material_name text NOT NULL,
  quantity text NOT NULL DEFAULT '',
  unit text NOT NULL DEFAULT 'Pcs',
  returnable boolean NOT NULL DEFAULT false,
  party_name text NOT NULL DEFAULT '',
  challan_no text NOT NULL DEFAULT '',
  vehicle_no text NOT NULL DEFAULT '',
  remarks text NOT NULL DEFAULT '',
  department text NOT NULL DEFAULT '',
  for_username text NOT NULL DEFAULT '',
  for_name text NOT NULL DEFAULT '',
  material_photo text NOT NULL DEFAULT '',
  bill_photo text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'Logged' CHECK (status IN ('Logged','Verified','Returned','Dispatched')),
  entered_by text NOT NULL DEFAULT 'Security Gate',
  verified_by text NOT NULL DEFAULT '',
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS material_gate_created_idx ON material_gate_passes(created_at DESC);
CREATE INDEX IF NOT EXISTS material_gate_dir_idx ON material_gate_passes(direction);
CREATE INDEX IF NOT EXISTS material_gate_factory_idx ON material_gate_passes(factory);
CREATE INDEX IF NOT EXISTS material_gate_dept_idx ON material_gate_passes(department);
