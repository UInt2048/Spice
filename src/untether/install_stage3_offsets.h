#ifndef INSTALL_STAGE3_OFFSETS
#define INSTALL_STAGE3_OFFSETS

// YOU NEED TO UPDATE THOSE WHEN YOU RECOMPILE STAGE 3
#define STAGE3_JUMP 0x6574 // nm of the function where_it_all_starts
#define STAGE3_CSBLOB 49744 // jtool --sig shows that info and I think we can get it when parsing the header
#define STAGE3_CSBLOB_SIZE 624 // same for this one

#endif