# D-01: observe duplicate-output refusal

The historical SRS left D-01 open because correct duplicate-detector firing had
not been observed. The new Transaction.ChangedInputsTriggerDuplicateOutputRefusal
native test drives the actual compile_output confirmation path. It accepts the
first output, accepts the same input/output repeat, then changes only the input
digest and observes the extra warning screen plus a -1 refusal even after both
screens are acknowledged. Its history is cleared on exit.

The focused test passes in 0.97 seconds. It compiles on the full product, using
the shared Bitcoin output code; existing Bitcoin-only host tests separately cover
repeat allowance and OP_RETURN history preservation. No detector implementation
or screen-count assertion was weakened. This resolves D-01's missing positive
observation for internal review. It does not claim a physical OLED run or a full
host signing test with two independently funded input transactions.
