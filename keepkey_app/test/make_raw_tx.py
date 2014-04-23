# Run with python make_raw_tx.py --testnet
from armoryengine import *

wallet_name = '/home/tom/.armory/testnet3/armory_2bZuo2ari_.wallet'

#
# Source bitcoin addresses for the transaction
#
source_addr_list = ['myHnTiAfku2nqLBvj4CA5DXiXKR1pdaAkW']

# 
# Destination bitcoin address for the transaction.
#
dest_list = [('mk5pFDdTFfnUke4fo9J4weqrX2vKLFokcE', long(1))]

# 
# The intermediate file that contains the transaction to be sent to the
# keepkey.
#
tx_dp_outfile = 'tx_armory_signed_out.dat'



def createTxFromAddrList(walletObj, addrList, recipList, \
                                          fee=0, changeAddr=None):
   #
   # Warning: Assumes the wallet is synced with the blockchain already.
   # Ensure that you've started armory up already, which does that 
   # automatically at startup.
   #

   # Check that all addresses are actually in the specified wallet
   print '\nVerifying transaction addresses.'
   for addr in addrList:
      addr160 = addrStr_to_hash160(addr)
      if not walletObj.hasAddr(addr160):
         raise WalletAddressError, 'Address is not in wallet! [%s]' % addr

   # 
   # Load the block chain
   #
   start = RightNow()
   TheBDM.setBlocking(True)
   TheBDM.setOnlineMode(True)
   # The setOnlineMode should block until blockchain loading is complete
   print 'Loading blockchain took %0.1f sec' % (RightNow() - start)

   topBlock = TheBDM.getTopBlockHeight()
   print '\n\nCurrent Top Block is:', topBlock
   TheBDM.getTopBlockHeader().pprint()

   print '\nCollecting Unspent TXOut List...'
   # getAddrTxOutList() returns a C++ vector<UnspentTxOut> object, which must 
   # be converted to a python object using the [:] notation:  it's a weird 
   # consequence of mixing C++ code with python via SWIG...
   utxoList = []
   for addr in addrList:
      addr160 = addrStr_to_hash160(addr)
      unspentTxOuts = walletObj.getAddrTxOutList(addr160, 'Spendable')
      utxoList.extend(unspentTxOuts[:])
   
   # Display what we found
   totalUtxo = sumTxOutList(utxoList)
   totalSpend   = sum([pair[1] for pair in recipList])
   print 'Available:  %d unspent outputs from %d addresses: %s BTC' % \
                  (len(utxoList), len(addrList), coin2str(totalUtxo, ndec=2))

   # Print more detailed information
   pprintUnspentTxOutList(utxoList, 'Available outputs: ')

def make_py_tx(recip160ValPairs):
    tx = PyTx()
    tx.version = 1
    tx.lockTime = 0
    tx.inputs = []
    tx.outputs = []

    # We can prepare the outputs, first
    for recipObj,value in recip160ValPairs:
        txout = PyTxOut()
        txout.value = long(value)

        # Assume recipObj is either a PBA or a string
        if isinstance(recipObj, PyBtcAddress):
            recipObj = recipObj.getAddr160()

        # Now recipObj is def a string
        if len(recipObj)!=20:
            # If not an address, it's a full script
            txout.binScript = recipObj
        else:
            # Construct a std TxOut from addr160 str
            txout.binScript = ''.join([  getOpCode('OP_DUP'        ), \
                                         getOpCode('OP_HASH160'    ), \
                                         '\x14',                      \
                                         recipObj,
                                         getOpCode('OP_EQUALVERIFY'), \
                                         getOpCode('OP_CHECKSIG'   )])
        thePyTx.outputs.append(txout)

    # Prepare the inputs based on the utxo objects
    for iin,utxo in enumerate(utxoSelection):
        # First, make sure that we have the previous Tx data available
        # We can't continue without it, since BIP 0010 will now require
        # the full tx of outputs being spent
        txin = PyTxIn()
        txin.outpoint = PyOutPoint()
        txin.binScript = ''
        txin.intSeq = 2**32-1

        txhash = utxo.getTxHash()
        txidx  = utxo.getTxOutIndex()
        txin.outpoint.txHash = str(txhash)
        txin.outpoint.txOutIndex = txidx
        thePyTx.inputs.append(txin)

    return self.createFromPyTx(thePyTx, txMap)

def sign_multisig_tx(wallet, tx_dp):
    wallet.signTxDistProposal(tx_dp)



def main():
    print "Opening armory wallet %s" % wallet_name
    armory_wallet = PyBtcWallet().readWalletFile(wallet_name)
    TheBDM.registerWallet(wlt)

    print "Creating unsigned transaction: "
    print "  Testnet test bitcoin     : " + source_addr_list[0]
    print "  Tx Unsigned Outfile      : " + tx_unsigned_outfile
    print "  Current blockchain state : " + TheBDM.getBDMState()
    #raw_tx = createTxFromAddrList(wlt, source_addr_list, dest_list)

    # Create multisig tx
    mstx = make_multisig_tx(armory_wallet, 2, source_addr_list, dest_list) 

    # Client sign tx
    sign_multisig_tx(armory_wallet, tx_dp)

    # Write 1 of 2 signed tx to file for sending to kk 
    outfile = open(tx_dp_outfile, 'w')
    outfile.write(tx_dp.serializeAscii())
    outfile.close()
    


    TheBDM.execCleanShutdown()

if __name__ == '__main__':
    main()


