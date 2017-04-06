#---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Author: Gergely Erdelyi <dyce@d-dome.net>
#---------------------------------------------------------------------
from idaapi import *

class MyDbgHook(DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        print "Break point at 0x%x pid=%d" % (ea, tid)

        if(ea == int("0x401228", 0)):
            # We are currently looking at a line with the entered password.
            # Look at each byte of the password.
            passadr = int("0x0040217E", 0)
            password = ""
            i = 0
            while(True):
                char = Byte(0x40217E + i)
                if (char == 0):
                    break
                else:
                    password = password + chr(char)
                    i = i + 1
            print "Entered password is: %s" % (password)
        # Make the password pass or fail.
        # If we are at the password check address, then
        if(ea == int("0x0040123F", 0)):
            
            #Password address is 0x0040217E
            esi = GetRegValue("esi")
            print("Entered Password is %X\n" % (esi))
            
            # Get the register value and check if it is 0.
            ecx = GetRegValue("ecx")
            print("ECX is [0x%X], %d\n" % (ecx, ecx))
            # If it is 0, then fail the test.
            if (ecx == 0):
                rv = idaapi.regval_t()
                rv.ival = 1
                idaapi.set_reg_val("ecx", rv)
            # If it is not zero, then pass the test.
            else:
                rv = idaapi.regval_t()
                rv.ival = 0
                idaapi.set_reg_val("ecx", rv)
        # Continue Debugging.
        return 0

# Remove an existing debug hook
try:
    if debughook:
        print "Removing previous hook ..."
        debughook.unhook()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# Stop at the entry point
ep = GetLongPrm(INF_START_IP)
request_run_to(ep)

# Step one instruction
request_step_over()

# Breakpoint before password is modified.
AddBpt(0x401228)
EnableBpt(0x401228, True)

# Breakpoint at test instruction.
AddBpt(0x40123F)
EnableBpt(0x40123F, True)

# Start debugging
run_requests()