CREATE TRIGGER quick_token_row_budget
BEFORE INSERT ON quick_tokens
WHEN (SELECT COUNT(*) FROM quick_tokens) >= 4096
BEGIN
    SELECT RAISE(ABORT, 'quick token capacity');
END;
