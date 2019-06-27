
randseed = %t
macro randomize {
randseed = randseed * 1103515245 + 12345
randseed = (randseed / 65536) mod 0x100000000
rndnum = randseed and 0xFFFFFFFF
}

macro Trash_String var, len {

 repeat len
        randomize
        vars = rndnum mod 0xFF
        db 'Key: 13371488',0
        db 'CrackMe',0
 end repeat
}

format binary as 'bin'
Trash_String a, 1024