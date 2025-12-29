CREATE TABLE IF NOT EXISTS users(
  email varchar(64) NOT NULL PRIMARY KEY,
  pw_hash varchar(64) NOT NULL,
  confirm_code char(32),
  is_confirmed bool NOT NULL DEFAULT false,
  created_at datetime DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_ratings(
  user_email varchar(64) NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  title_id varchar(16) NOT NULL,
  rating tinyint NOT NULL,
  updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_email, title_id),
  CHECK (rating BETWEEN -1 AND 2)
);