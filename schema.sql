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
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS requester_gender text NOT NULL DEFAULT '';
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS first_responded_at timestamptz;
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
  id_card_photos jsonb NOT NULL DEFAULT '[]'::jsonb,
  selfie_photos jsonb NOT NULL DEFAULT '[]'::jsonb,
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
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS id_card_photos jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE visitor_passes ADD COLUMN IF NOT EXISTS selfie_photos jsonb NOT NULL DEFAULT '[]'::jsonb;
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
  material_photos jsonb NOT NULL DEFAULT '[]'::jsonb,
  bill_photos jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'Logged' CHECK (status IN ('Logged','Verified','Returned','Dispatched')),
  entered_by text NOT NULL DEFAULT 'Security Gate',
  verified_by text NOT NULL DEFAULT '',
  verified_at timestamptz,
  expected_return_at timestamptz,
  expected_days integer NOT NULL DEFAULT 0,
  returned_at timestamptz,
  return_note text NOT NULL DEFAULT '',
  last_reminder_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE material_gate_passes ADD COLUMN IF NOT EXISTS expected_return_at timestamptz;
ALTER TABLE material_gate_passes ADD COLUMN IF NOT EXISTS expected_days integer NOT NULL DEFAULT 0;
ALTER TABLE material_gate_passes ADD COLUMN IF NOT EXISTS returned_at timestamptz;
ALTER TABLE material_gate_passes ADD COLUMN IF NOT EXISTS return_note text NOT NULL DEFAULT '';
ALTER TABLE material_gate_passes ADD COLUMN IF NOT EXISTS last_reminder_at timestamptz;
ALTER TABLE material_gate_passes ADD COLUMN IF NOT EXISTS material_photos jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE material_gate_passes ADD COLUMN IF NOT EXISTS bill_photos jsonb NOT NULL DEFAULT '[]'::jsonb;
CREATE INDEX IF NOT EXISTS material_gate_created_idx ON material_gate_passes(created_at DESC);
CREATE INDEX IF NOT EXISTS material_gate_dir_idx ON material_gate_passes(direction);
CREATE INDEX IF NOT EXISTS material_gate_factory_idx ON material_gate_passes(factory);
CREATE INDEX IF NOT EXISTS material_gate_dept_idx ON material_gate_passes(department);
CREATE INDEX IF NOT EXISTS material_gate_ret_due_idx ON material_gate_passes(returnable, expected_return_at);

CREATE TABLE IF NOT EXISTS vault_security_config (
  id integer PRIMARY KEY DEFAULT 1,
  initialized boolean NOT NULL DEFAULT false,
  pin_min_len integer NOT NULL DEFAULT 4,
  pin_max_len integer NOT NULL DEFAULT 8,
  pin_length integer NOT NULL DEFAULT 4,
  pin_hash text NOT NULL DEFAULT '',
  keyword_hash text NOT NULL DEFAULT '',
  kdf_salt text NOT NULL DEFAULT '',
  wrapped_dek_pin_kw text NOT NULL DEFAULT '',
  voice_enabled boolean NOT NULL DEFAULT false,
  voice_phrase_hash text NOT NULL DEFAULT '',
  voice_feature_enc text NOT NULL DEFAULT '',
  wrapped_dek_voice text NOT NULL DEFAULT '',
  failed_attempts integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL DEFAULT 5,
  permanently_locked boolean NOT NULL DEFAULT false,
  locked_at timestamptz,
  auto_lock_minutes integer NOT NULL DEFAULT 10,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vault_credentials (
  id text PRIMARY KEY,
  asset_tag text NOT NULL DEFAULT '',
  asset_name text NOT NULL DEFAULT '',
  device_type text NOT NULL DEFAULT '',
  factory text NOT NULL DEFAULT '',
  service_type text NOT NULL DEFAULT 'Web GUI',
  host_url text NOT NULL DEFAULT '',
  port text NOT NULL DEFAULT '',
  label text NOT NULL DEFAULT '',
  ciphertext text NOT NULL,
  created_by text NOT NULL DEFAULT '',
  updated_by text NOT NULL DEFAULT '',
  rotated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vault_creds_asset_idx ON vault_credentials(asset_tag);
CREATE INDEX IF NOT EXISTS vault_creds_factory_idx ON vault_credentials(factory);

CREATE TABLE IF NOT EXISTS device_firmware_backups (
  id text PRIMARY KEY,
  asset_tag text NOT NULL DEFAULT '',
  asset_name text NOT NULL DEFAULT '',
  device_type text NOT NULL DEFAULT '',
  manufacturer text NOT NULL DEFAULT '',
  model text NOT NULL DEFAULT '',
  factory text NOT NULL DEFAULT '',
  record_kind text NOT NULL DEFAULT 'Config Backup',
  firmware_version text NOT NULL DEFAULT '',
  previous_version text NOT NULL DEFAULT '',
  release_date text NOT NULL DEFAULT '',
  config_file_rel text NOT NULL DEFAULT '',
  config_file_name text NOT NULL DEFAULT '',
  config_file_size bigint NOT NULL DEFAULT 0,
  config_sha256 text NOT NULL DEFAULT '',
  config_format text NOT NULL DEFAULT '',
  firmware_file_rel text NOT NULL DEFAULT '',
  firmware_file_name text NOT NULL DEFAULT '',
  firmware_file_size bigint NOT NULL DEFAULT 0,
  firmware_sha256 text NOT NULL DEFAULT '',
  firmware_url text NOT NULL DEFAULT '',
  backup_taken_at text NOT NULL DEFAULT '',
  next_backup_due text NOT NULL DEFAULT '',
  eol_status text NOT NULL DEFAULT 'Supported',
  restore_steps text NOT NULL DEFAULT '',
  notes text NOT NULL DEFAULT '',
  uploaded_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS firmware_asset_idx ON device_firmware_backups(asset_tag);
CREATE INDEX IF NOT EXISTS firmware_factory_idx ON device_firmware_backups(factory);
CREATE INDEX IF NOT EXISTS firmware_kind_idx ON device_firmware_backups(record_kind);
CREATE INDEX IF NOT EXISTS firmware_updated_idx ON device_firmware_backups(updated_at DESC);

ALTER TABLE vault_security_config ADD COLUMN IF NOT EXISTS download_password_hash text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS vault_active_sessions (
  sid text PRIMARY KEY,
  username text NOT NULL DEFAULT '',
  wrapped_dek text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vault_sess_exp_idx ON vault_active_sessions(expires_at);

CREATE TABLE IF NOT EXISTS vault_doc_folders (
  id text PRIMARY KEY,
  parent_id text NOT NULL DEFAULT '',
  name text NOT NULL,
  color text NOT NULL DEFAULT '#157a54',
  icon text NOT NULL DEFAULT '📁',
  created_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vault_documents (
  id text PRIMARY KEY,
  folder_id text NOT NULL DEFAULT '',
  title text NOT NULL,
  orig_filename text NOT NULL,
  file_ext text NOT NULL DEFAULT '',
  mime_type text NOT NULL DEFAULT 'application/octet-stream',
  file_size bigint NOT NULL DEFAULT 0,
  sha256 text NOT NULL DEFAULT '',
  enc_rel_path text NOT NULL,
  meta_ciphertext text NOT NULL DEFAULT '',
  uploaded_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vault_docs_folder_idx ON vault_documents(folder_id);
CREATE INDEX IF NOT EXISTS vault_docs_updated_idx ON vault_documents(updated_at DESC);

CREATE TABLE IF NOT EXISTS vault_audit_logs (
  id bigserial PRIMARY KEY,
  event_type text NOT NULL,
  actor text NOT NULL DEFAULT '',
  target text NOT NULL DEFAULT '',
  detail text NOT NULL DEFAULT '',
  ip_address text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vault_audit_created_idx ON vault_audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS vault_user_security (
  username text PRIMARY KEY,
  initialized boolean NOT NULL DEFAULT false,
  pin_length integer NOT NULL DEFAULT 4,
  pin_hash text NOT NULL DEFAULT '',
  keyword_hash text NOT NULL DEFAULT '',
  kdf_salt text NOT NULL DEFAULT '',
  wrapped_dek_pin_kw text NOT NULL DEFAULT '',
  voice_enabled boolean NOT NULL DEFAULT false,
  voice_phrase_hash text NOT NULL DEFAULT '',
  voice_feature_enc text NOT NULL DEFAULT '',
  wrapped_dek_voice text NOT NULL DEFAULT '',
  download_password_hash text NOT NULL DEFAULT '',
  failed_attempts integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL DEFAULT 5,
  permanently_locked boolean NOT NULL DEFAULT false,
  locked_at timestamptz,
  auto_lock_minutes integer NOT NULL DEFAULT 10,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text NOT NULL DEFAULT ''
);

ALTER TABLE vault_credentials ADD COLUMN IF NOT EXISTS owner_username text NOT NULL DEFAULT '';
ALTER TABLE vault_credentials ADD COLUMN IF NOT EXISTS shared_item_key_enc text NOT NULL DEFAULT '';
ALTER TABLE vault_credentials ADD COLUMN IF NOT EXISTS shared_users jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE vault_credentials ADD COLUMN IF NOT EXISTS shared_depts jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS vault_creds_owner_idx ON vault_credentials(owner_username);

ALTER TABLE vault_doc_folders ADD COLUMN IF NOT EXISTS owner_username text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS vault_folders_owner_idx ON vault_doc_folders(owner_username);

ALTER TABLE vault_documents ADD COLUMN IF NOT EXISTS owner_username text NOT NULL DEFAULT '';
ALTER TABLE vault_documents ADD COLUMN IF NOT EXISTS shared_item_key_enc text NOT NULL DEFAULT '';
ALTER TABLE vault_documents ADD COLUMN IF NOT EXISTS shared_users jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE vault_documents ADD COLUMN IF NOT EXISTS shared_depts jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS vault_docs_owner_idx ON vault_documents(owner_username);

ALTER TABLE vault_audit_logs ADD COLUMN IF NOT EXISTS owner_scope text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS helpdesk_threads (
  id text PRIMARY KEY,
  requester_username text NOT NULL DEFAULT '',
  requester_name text NOT NULL DEFAULT '',
  requester_dept text NOT NULL DEFAULT '',
  requester_factory text NOT NULL DEFAULT '',
  requester_gender text NOT NULL DEFAULT '',
  section_id text NOT NULL DEFAULT 'it',
  section_label text NOT NULL DEFAULT 'IT Support',
  ticket_id text NOT NULL DEFAULT '',
  assigned_expert_username text NOT NULL DEFAULT '',
  assigned_expert_name text NOT NULL DEFAULT '',
  mode text NOT NULL DEFAULT 'bot',
  last_message_preview text NOT NULL DEFAULT '',
  last_message_at timestamptz NOT NULL DEFAULT now(),
  unread_for_requester integer NOT NULL DEFAULT 0,
  unread_for_staff integer NOT NULL DEFAULT 0,
  deleted_by_admin boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hd_threads_req_idx ON helpdesk_threads(requester_username, updated_at DESC);
CREATE INDEX IF NOT EXISTS hd_threads_sec_idx ON helpdesk_threads(section_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS hd_threads_exp_idx ON helpdesk_threads(assigned_expert_username, updated_at DESC);
CREATE INDEX IF NOT EXISTS hd_threads_tk_idx ON helpdesk_threads(ticket_id);

CREATE TABLE IF NOT EXISTS helpdesk_messages (
  id text PRIMARY KEY,
  thread_id text NOT NULL REFERENCES helpdesk_threads(id) ON DELETE CASCADE,
  sender_username text NOT NULL DEFAULT '',
  sender_name text NOT NULL DEFAULT '',
  sender_role text NOT NULL DEFAULT 'user',
  tagged_ticket_id text NOT NULL DEFAULT '',
  body text NOT NULL DEFAULT '',
  attachment_url text NOT NULL DEFAULT '',
  attachment_name text NOT NULL DEFAULT '',
  meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hd_msgs_thread_idx ON helpdesk_messages(thread_id, created_at ASC);
