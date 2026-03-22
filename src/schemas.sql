CREATE TABLE users(
  email varchar(64) not null primary key,
  pw_hash char(64) not null,
  confirm_code char(32),
  is_confirmed bool not null default false,
  created_at timestamp not null default now()
);

CREATE TABLE user_ratings(
  user_email varchar(64) not null references users(email) on delete cascade,
  title_id varchar(16) not null,
  rating int not null,
  updated_at timestamp not null default now(),
  primary key (user_email, title_id),
  check (rating BETWEEN -1 AND 2)
);