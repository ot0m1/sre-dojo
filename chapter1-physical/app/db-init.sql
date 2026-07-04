-- 起動時に一度だけ流し込まれる初期データ
CREATE TABLE IF NOT EXISTS products (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(100),
  price INT
);

INSERT INTO products (name, price) VALUES
  ('sword', 100),
  ('shield', 150),
  ('potion', 20),
  ('elixir', 500),
  ('map', 80);
