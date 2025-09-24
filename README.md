DB_HOST=127.0.0.1
DB_USER=testuser
DB_PASS=testpass
DB_NAME=sbomdb

DBの作成


-- スキャン履歴
CREATE TABLE scan (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL
);

-- コンポーネント情報
CREATE TABLE component (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tool VARCHAR(50) NOT NULL,
    component_name VARCHAR(255) NOT NULL,
    version VARCHAR(255),
    purl TEXT,
    hash_sha256 VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ライセンス情報
CREATE TABLE license (
    id INT AUTO_INCREMENT PRIMARY KEY,
    component_id INT NOT NULL,
    license_id VARCHAR(255) NOT NULL,
    FOREIGN KEY (component_id) REFERENCES component(id) ON DELETE CASCADE
);

-- 依存関係
CREATE TABLE dependencies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    parent_id INT NOT NULL,
    child_id INT NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES component(id) ON DELETE CASCADE,
    FOREIGN KEY (child_id) REFERENCES component(id) ON DELETE CASCADE
);

-- 生のSBOMデータ(JSON形式)
CREATE TABLE raw_sbom (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tool VARCHAR(50) NOT NULL,
    json_data JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
