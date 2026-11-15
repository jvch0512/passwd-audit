>>SOURCE FORMAT FREE
IDENTIFICATION DIVISION.
PROGRAM-ID. PASSWD-AUDIT.
*> Audits passwd and shadow style files. See README.md.

ENVIRONMENT DIVISION.
INPUT-OUTPUT SECTION.
FILE-CONTROL.
    SELECT ACCT-FILE ASSIGN TO DYNAMIC WS-PATH
        ORGANIZATION IS LINE SEQUENTIAL
        FILE STATUS IS WS-FS.

DATA DIVISION.
FILE SECTION.
FD ACCT-FILE.
01 ACCT-REC PIC X(1024).

WORKING-STORAGE SECTION.
01 WS-FS            PIC XX.
01 WS-PATH          PIC X(256).
01 WS-ARGC          PIC 9(4).
01 WS-ARG           PIC X(256).
01 WS-I             PIC 9(4).
01 WS-J             PIC 9(5).
01 WS-TSV           PIC 9 VALUE 0.
01 WS-FAIL-RANK     PIC 9 VALUE 9.
01 WS-WANT-FAIL     PIC 9 VALUE 0.
01 WS-BAD-ARGS      PIC 9 VALUE 0.
01 WS-NFILES        PIC 9(4) VALUE 0.
01 WS-FILES.
   05 WS-FILE-ENTRY OCCURS 20 TIMES.
      10 WS-FILE-PATH  PIC X(256).
      10 WS-FILE-LABEL PIC X(80).
01 WS-FIDX          PIC 9(4).
01 WS-EOF           PIC 9 VALUE 0.
01 WS-LINENO        PIC 9(9).
01 WS-LEN           PIC 9(5).
01 WS-NFIELDS       PIC 9(4).
01 WS-FIELDS.
   05 WS-F PIC X(300) OCCURS 11 TIMES.
01 WS-KIND          PIC 9.
01 WS-UID           PIC 9(9).
01 WS-UID-OK        PIC 9.
01 WS-TMP           PIC X(300).
01 WS-TMP2          PIC X(300).
01 WS-TLEN          PIC 9(5).
01 WS-NUM           PIC 9(9).
01 WS-USER-COUNT    PIC 9(5) VALUE 0.
01 WS-USERS.
   05 WS-U OCCURS 2000 TIMES.
      10 WS-U-NAME PIC X(40).
      10 WS-U-UID  PIC 9(9).
      10 WS-U-HAS  PIC 9.
01 WS-NF            PIC 9(5) VALUE 0.
01 WS-FINDINGS.
   05 WS-FND OCCURS 1500 TIMES.
      10 FND-RANK PIC 9.
      10 FND-FILE PIC 9(4).
      10 FND-RULE PIC X(6).
      10 FND-LINE PIC 9(9).
      10 FND-MSG  PIC X(160).
01 WS-NEW-RANK      PIC 9.
01 WS-NEW-RULE      PIC X(6).
01 WS-NEW-MSG       PIC X(160).
01 WS-SEV           PIC X(8).
01 WS-SEVUP         PIC X(8).
01 WS-LINE-ED       PIC Z(8)9.
01 WS-LINE-TXT      PIC X(12).
01 WS-COUNT-ED      PIC Z(4)9.
01 WS-OUT           PIC X(400).
01 WS-TAB           PIC X VALUE X"09".
01 WS-RANK-LOOP     PIC 9.
01 WS-FILE-LOOP     PIC 9(4).
01 WS-DUP           PIC 9.
01 WS-SHELL-OK      PIC 9.
01 WS-POS           PIC 9(5).
01 WS-LAST-SLASH    PIC 9(5).

PROCEDURE DIVISION.
MAIN.
    PERFORM PARSE-ARGS
    IF WS-BAD-ARGS = 1 OR WS-NFILES = 0
        PERFORM USAGE-EXIT
    END-IF
    PERFORM VARYING WS-FIDX FROM 1 BY 1 UNTIL WS-FIDX > WS-NFILES
        MOVE WS-FILE-PATH(WS-FIDX) TO WS-PATH
        OPEN INPUT ACCT-FILE
        IF WS-FS NOT = "00"
            DISPLAY "error: no such file or directory: " FUNCTION TRIM(WS-PATH) UPON SYSERR
            MOVE 2 TO RETURN-CODE
            STOP RUN
        END-IF
        PERFORM PROCESS-FILE
        CLOSE ACCT-FILE
    END-PERFORM
    PERFORM PRINT-REPORT
    STOP RUN.

USAGE-EXIT.
    DISPLAY "usage: passwd-audit FILE [FILE...] [--tsv] [--fail-on medium|high|critical]" UPON SYSERR
    DISPLAY "Exit: 0 ok, 1 findings at or above --fail-on, 2 bad input." UPON SYSERR
    MOVE 2 TO RETURN-CODE
    STOP RUN.

PARSE-ARGS.
    ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
    MOVE 1 TO WS-I
    PERFORM UNTIL WS-I > WS-ARGC OR WS-BAD-ARGS = 1
        MOVE SPACES TO WS-ARG
        ACCEPT WS-ARG FROM ARGUMENT-VALUE
        EVALUATE TRUE
            WHEN WS-ARG = "--tsv"
                MOVE 1 TO WS-TSV
            WHEN WS-ARG = "--fail-on"
                ADD 1 TO WS-I
                MOVE SPACES TO WS-ARG
                IF WS-I > WS-ARGC
                    MOVE 1 TO WS-BAD-ARGS
                ELSE
                    ACCEPT WS-ARG FROM ARGUMENT-VALUE
                    EVALUATE TRUE
                        WHEN WS-ARG = "medium"   MOVE 2 TO WS-FAIL-RANK
                        WHEN WS-ARG = "high"     MOVE 1 TO WS-FAIL-RANK
                        WHEN WS-ARG = "critical" MOVE 0 TO WS-FAIL-RANK
                        WHEN OTHER               MOVE 1 TO WS-BAD-ARGS
                    END-EVALUATE
                    MOVE 1 TO WS-WANT-FAIL
                END-IF
            WHEN WS-ARG(1:1) = "-"
                MOVE 1 TO WS-BAD-ARGS
            WHEN OTHER
                IF WS-NFILES >= 20
                    MOVE 1 TO WS-BAD-ARGS
                ELSE
                    ADD 1 TO WS-NFILES
                    MOVE WS-ARG TO WS-FILE-PATH(WS-NFILES)
                    PERFORM SET-LABEL
                END-IF
        END-EVALUATE
        ADD 1 TO WS-I
    END-PERFORM.

SET-LABEL.
    *> label is the part of the path after the last slash
    MOVE 0 TO WS-LAST-SLASH
    PERFORM VARYING WS-POS FROM 1 BY 1 UNTIL WS-POS > 256
        IF WS-ARG(WS-POS:1) = "/"
            MOVE WS-POS TO WS-LAST-SLASH
        END-IF
    END-PERFORM
    MOVE SPACES TO WS-FILE-LABEL(WS-NFILES)
    MOVE WS-ARG(WS-LAST-SLASH + 1:) TO WS-FILE-LABEL(WS-NFILES).

PROCESS-FILE.
    MOVE 0 TO WS-EOF
    MOVE 0 TO WS-LINENO
    MOVE 0 TO WS-USER-COUNT
    PERFORM UNTIL WS-EOF = 1
        MOVE SPACES TO ACCT-REC
        READ ACCT-FILE
            AT END MOVE 1 TO WS-EOF
            NOT AT END
                ADD 1 TO WS-LINENO
                PERFORM HANDLE-LINE
        END-READ
    END-PERFORM.

HANDLE-LINE.
    IF ACCT-REC = SPACES OR ACCT-REC(1:1) = "#"
        EXIT PARAGRAPH
    END-IF
    MOVE SPACES TO WS-FIELDS
    MOVE 0 TO WS-NFIELDS
    UNSTRING ACCT-REC DELIMITED BY ":"
        INTO WS-F(1) WS-F(2) WS-F(3) WS-F(4) WS-F(5) WS-F(6)
             WS-F(7) WS-F(8) WS-F(9) WS-F(10) WS-F(11)
        TALLYING IN WS-NFIELDS
    END-UNSTRING
    EVALUATE TRUE
        WHEN WS-NFIELDS = 7 AND WS-F(1) NOT = SPACES
            PERFORM CHECK-PASSWD
        WHEN WS-NFIELDS = 9 AND WS-F(1) NOT = SPACES
            PERFORM CHECK-SHADOW
        WHEN OTHER
            MOVE 4 TO WS-NEW-RANK
            MOVE "PWD000" TO WS-NEW-RULE
            MOVE "not a passwd or shadow entry (expected 7 or 9 colon separated fields), ignored" TO WS-NEW-MSG
            PERFORM ADD-FINDING
    END-EVALUATE.

PARSE-NUMBER.
    *> input WS-TMP (trimmed text); output WS-UID-OK, WS-NUM
    MOVE 0 TO WS-UID-OK
    MOVE 0 TO WS-NUM
    MOVE FUNCTION TRIM(WS-TMP) TO WS-TMP2
    COMPUTE WS-TLEN = FUNCTION LENGTH(FUNCTION TRIM(WS-TMP))
    IF WS-TMP2 = SPACES OR WS-TLEN > 9
        EXIT PARAGRAPH
    END-IF
    IF WS-TMP2(1:WS-TLEN) IS NUMERIC
        MOVE WS-TMP2(1:WS-TLEN) TO WS-NUM
        MOVE 1 TO WS-UID-OK
    END-IF.

CHECK-PASSWD.
    MOVE WS-F(3) TO WS-TMP
    PERFORM PARSE-NUMBER
    MOVE WS-NUM TO WS-UID
    IF WS-UID-OK = 1 AND WS-UID = 0 AND FUNCTION TRIM(WS-F(1)) NOT = "root"
        MOVE 1 TO WS-NEW-RANK
        MOVE "PWD001" TO WS-NEW-RULE
        MOVE SPACES TO WS-NEW-MSG
        STRING "account " FUNCTION TRIM(WS-F(1)) " has UID 0 but is not root: it is a second superuser"
            DELIMITED BY SIZE INTO WS-NEW-MSG
        PERFORM ADD-FINDING
    END-IF
    IF WS-F(2) = SPACES
        MOVE 1 TO WS-NEW-RANK
        MOVE "PWD002" TO WS-NEW-RULE
        MOVE SPACES TO WS-NEW-MSG
        STRING "account " FUNCTION TRIM(WS-F(1)) " has an empty password field: it can log in without a password"
            DELIMITED BY SIZE INTO WS-NEW-MSG
        PERFORM ADD-FINDING
    ELSE
        IF FUNCTION TRIM(WS-F(2)) NOT = "x" AND FUNCTION TRIM(WS-F(2)) NOT = "*"
           AND FUNCTION TRIM(WS-F(2)) NOT = "!" AND FUNCTION TRIM(WS-F(2)) NOT = "!!"
            MOVE 2 TO WS-NEW-RANK
            MOVE "PWD003" TO WS-NEW-RULE
            MOVE SPACES TO WS-NEW-MSG
            STRING "account " FUNCTION TRIM(WS-F(1)) " keeps a password hash in passwd, which every user can read"
                DELIMITED BY SIZE INTO WS-NEW-MSG
            PERFORM ADD-FINDING
        END-IF
    END-IF
    IF WS-UID-OK = 1 AND WS-UID > 0 AND WS-UID < 1000
        PERFORM CHECK-SHELL
        IF WS-SHELL-OK = 1
            MOVE 2 TO WS-NEW-RANK
            MOVE "PWD005" TO WS-NEW-RULE
            MOVE SPACES TO WS-NEW-MSG
            STRING "system account " FUNCTION TRIM(WS-F(1)) " (UID " FUNCTION TRIM(WS-F(3))
                ") has an interactive shell: " FUNCTION TRIM(WS-F(7))
                DELIMITED BY SIZE INTO WS-NEW-MSG
            PERFORM ADD-FINDING
        END-IF
    END-IF
    PERFORM CHECK-DUPLICATES.

CHECK-SHELL.
    *> sets WS-SHELL-OK = 1 when field 7 names an interactive shell
    MOVE 0 TO WS-SHELL-OK
    MOVE FUNCTION TRIM(WS-F(7)) TO WS-TMP
    COMPUTE WS-TLEN = FUNCTION LENGTH(FUNCTION TRIM(WS-F(7)))
    IF WS-F(7) = SPACES
        EXIT PARAGRAPH
    END-IF
    IF WS-TLEN >= 3 AND WS-TMP(WS-TLEN - 1:2) = "sh"
        MOVE 1 TO WS-SHELL-OK
    END-IF
    IF WS-TMP(1:WS-TLEN) = "/bin/false" OR WS-TMP(1:WS-TLEN) = "/usr/sbin/nologin"
       OR WS-TMP(1:WS-TLEN) = "/sbin/nologin" OR WS-TMP(1:WS-TLEN) = "/bin/sync"
        MOVE 0 TO WS-SHELL-OK
    END-IF.

CHECK-DUPLICATES.
    IF WS-USER-COUNT < 2000
        ADD 1 TO WS-USER-COUNT
        MOVE FUNCTION TRIM(WS-F(1)) TO WS-U-NAME(WS-USER-COUNT)
        MOVE WS-NUM TO WS-U-UID(WS-USER-COUNT)
        MOVE WS-UID-OK TO WS-U-HAS(WS-USER-COUNT)
        MOVE 0 TO WS-DUP
        PERFORM VARYING WS-J FROM 1 BY 1 UNTIL WS-J >= WS-USER-COUNT OR WS-DUP = 1
            IF WS-U-UID(WS-J) = WS-NUM AND WS-U-HAS(WS-J) = 1 AND WS-UID-OK = 1
                MOVE 1 TO WS-DUP
                MOVE 2 TO WS-NEW-RANK
                MOVE "PWD006" TO WS-NEW-RULE
                MOVE SPACES TO WS-NEW-MSG
                STRING "UID " FUNCTION TRIM(WS-F(3)) " is shared by " FUNCTION TRIM(WS-U-NAME(WS-J))
                    " and " FUNCTION TRIM(WS-F(1)) ": they are the same identity to the kernel"
                    DELIMITED BY SIZE INTO WS-NEW-MSG
                PERFORM ADD-FINDING
            END-IF
        END-PERFORM
        MOVE 0 TO WS-DUP
        PERFORM VARYING WS-J FROM 1 BY 1 UNTIL WS-J >= WS-USER-COUNT OR WS-DUP = 1
            IF WS-U-NAME(WS-J) = FUNCTION TRIM(WS-F(1))
                MOVE 1 TO WS-DUP
                MOVE 2 TO WS-NEW-RANK
                MOVE "PWD008" TO WS-NEW-RULE
                MOVE SPACES TO WS-NEW-MSG
                STRING "user name " FUNCTION TRIM(WS-F(1)) " appears more than once"
                    DELIMITED BY SIZE INTO WS-NEW-MSG
                PERFORM ADD-FINDING
            END-IF
        END-PERFORM
    END-IF.

CHECK-SHADOW.
    IF WS-F(2) = SPACES
        MOVE 1 TO WS-NEW-RANK
        MOVE "PWD002" TO WS-NEW-RULE
        MOVE SPACES TO WS-NEW-MSG
        STRING "account " FUNCTION TRIM(WS-F(1)) " has an empty password hash: it can log in without a password"
            DELIMITED BY SIZE INTO WS-NEW-MSG
        PERFORM ADD-FINDING
        EXIT PARAGRAPH
    END-IF
    IF WS-F(2)(1:1) = "!" OR WS-F(2)(1:1) = "*"
        EXIT PARAGRAPH
    END-IF
    COMPUTE WS-TLEN = FUNCTION LENGTH(FUNCTION TRIM(WS-F(2)))
    IF WS-F(2)(1:3) = "$1$"
        MOVE 1 TO WS-NEW-RANK
        MOVE "PWD004" TO WS-NEW-RULE
        MOVE SPACES TO WS-NEW-MSG
        STRING "account " FUNCTION TRIM(WS-F(1)) " uses an MD5 crypt hash ($1$): crack it with commodity hardware"
            DELIMITED BY SIZE INTO WS-NEW-MSG
        PERFORM ADD-FINDING
    ELSE
        IF WS-F(2)(1:1) NOT = "$" AND WS-TLEN = 13
            MOVE 1 TO WS-NEW-RANK
            MOVE "PWD004" TO WS-NEW-RULE
            MOVE SPACES TO WS-NEW-MSG
            STRING "account " FUNCTION TRIM(WS-F(1)) " uses a traditional DES hash: only 8 characters count"
                DELIMITED BY SIZE INTO WS-NEW-MSG
            PERFORM ADD-FINDING
        END-IF
    END-IF
    IF WS-F(2)(1:1) = "$" OR WS-TLEN = 13
        MOVE WS-F(5) TO WS-TMP
        PERFORM PARSE-NUMBER
        IF WS-F(5) = SPACES OR (WS-UID-OK = 1 AND WS-NUM >= 99999)
            MOVE 3 TO WS-NEW-RANK
            MOVE "PWD007" TO WS-NEW-RULE
            MOVE SPACES TO WS-NEW-MSG
            STRING "account " FUNCTION TRIM(WS-F(1)) " has a password that never expires"
                DELIMITED BY SIZE INTO WS-NEW-MSG
            PERFORM ADD-FINDING
        END-IF
    END-IF.

ADD-FINDING.
    IF WS-NF < 1500
        ADD 1 TO WS-NF
        MOVE WS-NEW-RANK TO FND-RANK(WS-NF)
        MOVE WS-FIDX TO FND-FILE(WS-NF)
        MOVE WS-NEW-RULE TO FND-RULE(WS-NF)
        MOVE WS-LINENO TO FND-LINE(WS-NF)
        MOVE WS-NEW-MSG TO FND-MSG(WS-NF)
    END-IF.

PRINT-REPORT.
    MOVE WS-NF TO WS-COUNT-ED
    MOVE SPACES TO WS-OUT
    MOVE WS-NFILES TO WS-LINE-ED
    IF WS-TSV = 1
        STRING "# " FUNCTION TRIM(WS-LINE-ED) " files, " FUNCTION TRIM(WS-COUNT-ED) " findings"
            DELIMITED BY SIZE INTO WS-OUT
    ELSE
        STRING FUNCTION TRIM(WS-LINE-ED) " files, " FUNCTION TRIM(WS-COUNT-ED) " findings"
            DELIMITED BY SIZE INTO WS-OUT
    END-IF
    DISPLAY FUNCTION TRIM(WS-OUT)
    PERFORM VARYING WS-RANK-LOOP FROM 0 BY 1 UNTIL WS-RANK-LOOP > 4
        PERFORM VARYING WS-FILE-LOOP FROM 1 BY 1 UNTIL WS-FILE-LOOP > WS-NFILES
            PERFORM VARYING WS-J FROM 1 BY 1 UNTIL WS-J > WS-NF
                IF FND-RANK(WS-J) = WS-RANK-LOOP AND FND-FILE(WS-J) = WS-FILE-LOOP
                    PERFORM PRINT-ONE
                END-IF
            END-PERFORM
        END-PERFORM
    END-PERFORM
    IF WS-WANT-FAIL = 1
        PERFORM VARYING WS-J FROM 1 BY 1 UNTIL WS-J > WS-NF
            IF FND-RANK(WS-J) <= WS-FAIL-RANK
                MOVE 1 TO RETURN-CODE
            END-IF
        END-PERFORM
    END-IF.

PRINT-ONE.
    EVALUATE FND-RANK(WS-J)
        WHEN 0 MOVE "critical" TO WS-SEV
        WHEN 1 MOVE "high"     TO WS-SEV
        WHEN 2 MOVE "medium"   TO WS-SEV
        WHEN 3 MOVE "low"      TO WS-SEV
        WHEN OTHER MOVE "info" TO WS-SEV
    END-EVALUATE
    MOVE FND-LINE(WS-J) TO WS-LINE-ED
    MOVE SPACES TO WS-OUT
    IF WS-TSV = 1
        STRING FUNCTION TRIM(WS-SEV) WS-TAB FND-RULE(WS-J) WS-TAB
            FUNCTION TRIM(WS-FILE-LABEL(WS-FILE-LOOP)) ":" FUNCTION TRIM(WS-LINE-ED) WS-TAB
            FUNCTION TRIM(FND-MSG(WS-J))
            DELIMITED BY SIZE INTO WS-OUT
        DISPLAY FUNCTION TRIM(WS-OUT)
    ELSE
        MOVE FUNCTION UPPER-CASE(WS-SEV) TO WS-SEVUP
        STRING WS-SEVUP " " FND-RULE(WS-J) " "
            FUNCTION TRIM(WS-FILE-LABEL(WS-FILE-LOOP)) ":" FUNCTION TRIM(WS-LINE-ED)
            DELIMITED BY SIZE INTO WS-OUT
        DISPLAY FUNCTION TRIM(WS-OUT TRAILING)
        MOVE SPACES TO WS-OUT
        STRING "         " FUNCTION TRIM(FND-MSG(WS-J)) DELIMITED BY SIZE INTO WS-OUT
        DISPLAY FUNCTION TRIM(WS-OUT TRAILING)
    END-IF.
