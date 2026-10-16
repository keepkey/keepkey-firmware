#ifndef STORAGE_VERSION_ENTRY
#define STORAGE_VERSION_ENTRY(X)
#endif

#ifndef STORAGE_VERSION_LAST
#define STORAGE_VERSION_LAST(X) STORAGE_VERSION_ENTRY(X)
#endif

STORAGE_VERSION_ENTRY(1)
STORAGE_VERSION_ENTRY(2)
STORAGE_VERSION_ENTRY(3)
STORAGE_VERSION_ENTRY(4)
STORAGE_VERSION_ENTRY(5)
STORAGE_VERSION_ENTRY(6)
STORAGE_VERSION_ENTRY(7)
STORAGE_VERSION_ENTRY(8)
STORAGE_VERSION_ENTRY(9)
STORAGE_VERSION_ENTRY(10)
STORAGE_VERSION_ENTRY(11)
STORAGE_VERSION_ENTRY(12)
STORAGE_VERSION_ENTRY(13)
STORAGE_VERSION_ENTRY(14)
STORAGE_VERSION_ENTRY(15)
STORAGE_VERSION_ENTRY(16)
STORAGE_VERSION_ENTRY(17)
/* 18 and 19 are BURNED. They were the clear-sign identity block and the PIN-KDF
 * migration, both active in alpha builds before 6bebde7b2 reverted the format
 * to V17. Devices that ran those builds carry blobs stamped 18 or 19 with a
 * layout that has nothing to do with passkeys, so reusing either number would
 * make this firmware misparse them. They stay in the ladder because the enum is
 * positional -- removing one renumbers everything after it. */
STORAGE_VERSION_ENTRY(18)
STORAGE_VERSION_ENTRY(19)
STORAGE_VERSION_LAST(20)


#undef STORAGE_VERSION_ENTRY
#undef STORAGE_VERSION_LAST
