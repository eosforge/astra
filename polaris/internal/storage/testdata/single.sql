-- Independent single-key format vector: one 3-byte live record and one 67-byte history charge.
INSERT INTO meta VALUES(1,1,'test','polaris','127.0.0.1:45101',1,3);
INSERT INTO scopes VALUES('release','baseline',X'0000000000000001',1,3,1,67);
INSERT INTO records VALUES('release','baseline','a',X'0001');
INSERT INTO history VALUES('release','baseline',X'0000000000000001','a',X'0001',0,67);
