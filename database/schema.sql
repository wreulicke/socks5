CREATE TABLE user_password_hashes (
    username VARCHAR(255) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL
);