CREATE TABLE IPS_BLOQUEADOS (
    ID INTEGER GENERATED BY DEFAULT AS IDENTITY NOT NULL,
    IP VARCHAR(45) NOT NULL UNIQUE,
    DATA_BLOQUEIO TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    MOTIVO VARCHAR(255),
    TENTATIVAS INTEGER DEFAULT 1,
    CONSTRAINT PK_IPS_BLOQUEADOS PRIMARY KEY (ID)
);


CREATE TABLE HIDAN_GUARD_LOGS (
	ID INTEGER GENERATED BY DEFAULT AS IDENTITY NOT NULL,
	IP_ATAQUE VARCHAR(45) NOT NULL,
	DATA_ATAQUE TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	TIPO_ATAQUE VARCHAR(50) NOT NULL,
	DETALHES BLOB SUB_TYPE TEXT,
	BLOQUEADO BOOLEAN DEFAULT TRUE,
	RITUAL_COMPLETO BOOLEAN DEFAULT FALSE,
	CONSTRAINT INTEG_143 PRIMARY KEY (ID)
);
CREATE UNIQUE INDEX RDB$PRIMARY54 ON HIDAN_GUARD_LOGS (ID);