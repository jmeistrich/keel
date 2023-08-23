CREATE OR REPLACE FUNCTION process_audit() RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO "keel_audit" (table_name, op, data)
        SELECT TG_TABLE_NAME, 'delete', row_to_json(o.*)
        FROM old_table o;                                                                 
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO "keel_audit" (table_name, op, data)                                                                                                                                                                 
        SELECT TG_TABLE_NAME, 'update', row_to_json(n.*)
        FROM new_table n;                                                                 
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO "keel_audit" (table_name, op, data)                                                                                                                                                                 
        SELECT TG_TABLE_NAME, 'insert', row_to_json(n.*)
        FROM new_table n;                                                                 
    END IF;                                                                                                                                                                              
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;