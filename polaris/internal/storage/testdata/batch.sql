-- Independently encoded AB02 vector: Set a=0001, Set b=empty, Delete c, all at version one.
-- The 38-byte body has three entries and one 102-byte history charge; live a/b total four bytes.
INSERT INTO meta VALUES(1,1,'test','polaris','127.0.0.1:45101',1,4);
INSERT INTO scopes VALUES('release','baseline',X'0000000000000001',2,4,1,102);
INSERT INTO records VALUES('release','baseline','a',X'0001');
INSERT INTO records VALUES('release','baseline','b',X'');
INSERT INTO history VALUES('release','baseline',X'0000000000000001','',X'4142303200000000000000030001000000020061000100010000000000620001000000000163',0,102);
