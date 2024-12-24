-- Users Table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reset_token | varchar(255) | YES | | NULL | | | 
    reset_token_expiry | datetime | YES | | NULL |
);
-- Blogs Table
CREATE TABLE blogs (
    id int NOT NULL AUTO_INCREMENT,
    title varchar(255) NOT NULL,
    subtitle varchar(255) DEFAULT NULL,
    short_description text DEFAULT NULL,
    content text NOT NULL,
    author varchar(255) NOT NULL,
    user_id int NOT NULL,
    img varchar(255) DEFAULT NULL,
    category varchar(100) DEFAULT NULL,
    tags varchar(255) DEFAULT NULL,
    owner_username varchar(255) DEFAULT NULL,
    PRIMARY KEY (id)
);


-- Create Conversations Table
CREATE TABLE conversations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user1_id INT NOT NULL,
    user2_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create Messages Table
CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    conversation_id INT NOT NULL,
    sender_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

ALTER TABLE messages
ADD COLUMN media VARCHAR(255) DEFAULT NULL;  -- Adjust the data type as needed, e.g., VARCHAR for URLs, BLOB for binary data.

