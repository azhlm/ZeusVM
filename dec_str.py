import struct
from binaryninja import LowLevelILOperation, LowLevelILInstruction

class DecStr:
    
    def __init__(self, bv):
        self.bv = bv
        self.decryptor = None
        self.string_buffer = None
        self.struct_count = 0
        self.enum_type = None
        self.registered_name = None  # Store the registered name of the enum type

    def find_decryptor(self, func_llil):
        
        def match_LowLevelIL_416995_0(insn):
            try:
                if insn.operation != LowLevelILOperation.LLIL_SET_REG:
                    return False
                if insn.src.left.operation != LowLevelILOperation.LLIL_REG:
                    return False
                if insn.src.right.operation != LowLevelILOperation.LLIL_REG:
                    return False
                return True
            except AttributeError:
                return False
            
        def match_LowLevelIL_416998_0(insn):
            try:
                if insn.operation != LowLevelILOperation.LLIL_STORE:
                    return False
                if insn.dest.operation != LowLevelILOperation.LLIL_ADD:
                    return False
                if insn.dest.left.operation != LowLevelILOperation.LLIL_REG:
                    return False
                if insn.dest.right.operation != LowLevelILOperation.LLIL_LSL:
                    return False
                if insn.dest.right.left.operation != LowLevelILOperation.LLIL_REG:
                    return False
                if insn.dest.right.right.operation != LowLevelILOperation.LLIL_CONST:
                    return False
                if insn.dest.right.right.constant != 0x1:
                    return False
                if insn.src.operation != LowLevelILOperation.LLIL_REG:
                    return False
                return True
            except AttributeError:
                return False
            
        Found = False
        for bb in func_llil:
            for insn in bb:
                if match_LowLevelIL_416995_0(insn):
                    dest_name = insn.dest.name
                    Found = True
                    continue
                if Found and match_LowLevelIL_416998_0(insn):
                    return True
                else:
                    Found = False
        return False

    def find_string_buffer(self, func_llil):
        
        def match_LowLevelIL_416957_0(insn):
            try:
                # eax = eax + 0x4019e0
                if insn.operation != LowLevelILOperation.LLIL_SET_REG:
                    return False
                if insn.src.operation != LowLevelILOperation.LLIL_ADD:
                    return False
                if insn.src.left.operation != LowLevelILOperation.LLIL_REG:
                    return False
                if insn.src.right.operation != LowLevelILOperation.LLIL_CONST:
                    return False
                if insn.src.right.constant < 0x400000:
                    return False
                return True
            except AttributeError:
                return False

        for bb in func_llil:
            for insn in bb:
                if match_LowLevelIL_416957_0(insn):
                    # print(f"Found string buffer at {insn.src.right.constant:#x}")
                    return insn.src.right.constant
        return None

    def convert_struct(self):
        
        def check_all_zero_little_endian(byte_data):
            if len(byte_data) != 12:
                raise ValueError("Input must be exactly 12 bytes.")
            # Unpack as three little-endian unsigned integers
            values = struct.unpack('<III', byte_data)
            return not any(values)
                
        def define_struct():
            """
            struct string __packed
            {
                byte xorkey[0x4];
                int16_t string_len;
                int16_t pad;
                char* string_enc;
            };
            """
            # Use the correct Binary Ninja API to parse types
            struct_definition = \
            """struct string
                {
                    char xorkey[4];
                    int16_t string_len;
                    int16_t pad;
                    char* string_enc;
                } __attribute__((packed));"""
            try:
                # Use the correct method to parse types
                parsed_types = self.bv.parse_types_from_string(struct_definition)
                if 'string' in parsed_types.types:
                    struct_type = parsed_types.types['string']
                    self.bv.define_user_type("string", struct_type)
                    print("[*] Struct 'string' defined successfully using parse_types_from_string")
                    return struct_type
            except Exception as e:
                print(f"[!] parse_types_from_string failed: {e}")
            # Alternative: Try with different syntax
            try:
                struct_definition2 = \
                """typedef struct __attribute__((packed))
                        {
                            char xorkey[4];
                            short string_len;
                            short pad;
                            char* string_enc;
                        } string;"""
                parsed_types = self.bv.parse_types_from_string(struct_definition2)
                if 'string' in parsed_types.types:
                    struct_type = parsed_types.types['string']
                    self.bv.define_user_type("string", struct_type)
                    print("[*] Struct 'string' defined successfully using typedef syntax")
                    return struct_type
            except Exception as e:
                print(f"[!] typedef syntax failed: {e}")
            # Final fallback: Create proper struct manually using correct API
            from binaryninja import Type
            import binaryninja
            try:
                # Create structure members using the correct format
                # Use StructureMember objects
                members = []
                # xorkey field
                xorkey_type = Type.array(Type.int(1, False), 4)
                members.append(binaryninja.StructureMember(xorkey_type, "xorkey"))
                # string_len field  
                string_len_type = Type.int(2, True)
                members.append(binaryninja.StructureMember(string_len_type, "string_len"))
                # pad field
                pad_type = Type.int(2, True) 
                members.append(binaryninja.StructureMember(pad_type, "pad"))
                # string_enc field
                char_ptr_type = Type.pointer(self.bv.arch, Type.int(1, True))
                members.append(binaryninja.StructureMember(char_ptr_type, "string_enc"))
                # Create the structure with packed=True
                struct_type = Type.structure_type(members, packed=True)
                self.bv.define_user_type("string", struct_type)
                print("[*] Struct 'string' defined successfully using StructureMember objects")
                return struct_type
            except Exception as e:
                print(f"[!] StructureMember method failed: {e}")
                print("[*] Creating basic struct without packed attribute")
                # Last resort: create basic struct
                try:
                    members = []
                    members.append(binaryninja.StructureMember(Type.array(Type.int(1, False), 4), "xorkey"))
                    members.append(binaryninja.StructureMember(Type.int(2, True), "string_len"))
                    members.append(binaryninja.StructureMember(Type.int(2, True), "pad"))
                    members.append(binaryninja.StructureMember(Type.pointer(self.bv.arch, Type.int(1, True)), "string_enc"))

                    struct_type = Type.structure_type(members)
                    self.bv.define_user_type("string", struct_type)
                    print("[*] Struct 'string' defined successfully (basic struct, may have padding)")
                    return struct_type
                except Exception as e:
                    print(f"[!] All methods failed: {e}")
                    return None
        
        struct_type = define_struct()
        if not struct_type:
            print("[!] Failed to define struct 'string'.")
            return
        
        buffer_addr = self.string_buffer
        while True:
            byte_data = self.bv.read(buffer_addr, 12)
            if not byte_data:
                print("[!] No more data to read.")
                break

            if not check_all_zero_little_endian(byte_data):
                self.struct_count += 1
            else:
                print("[*] Found zero value, stopping conversion.")
                break

            buffer_addr += 12

        print(f"[*] Converted {self.struct_count} structures.")
        self.bv.define_user_data_var(self.string_buffer, f"string [{self.struct_count}]")
        return 

    def Start(self):
        for func in self.bv.functions:
            if self.find_decryptor(func.llil):
                self.decryptor = func
                self.decryptor.name = "mw_resolve_string"
                print(f"[*] Found decryptor at {func.start:#x}")
                
                self.string_buffer = self.find_string_buffer(func.llil)
                if self.string_buffer:
                    print(f"[*] Found string buffer at {self.string_buffer:#x}")
                else:
                    print("[!] String buffer not found.")
                    
        if not self.decryptor:
            print("[!] Decryptor not found.")
            return
        
        if not self.string_buffer:
            print("[!] String buffer not found.")
            return
        
        self.convert_struct()
        self.bv.update_analysis_and_wait()

        dec_members = []
        print("[*] Analysis updated after struct conversion.")
        structs = self.bv.get_data_var_at(self.string_buffer)
        for idx, struct in enumerate(structs):
            xorkey = struct['xorkey'].value
            string_len = struct['string_len'].value
            string_enc = struct['string_enc'].value
            string_dec = None
            try:
                if string_enc > 0x400000:
                    string_data = self.bv.read(string_enc, string_len)
                    if string_data:
                        decrypted_string = bytearray()
                        for i in range(string_len):
                            decrypted_string.append(string_data[i] ^ xorkey[string_len & 0x3] ^ i)
                        string_dec = decrypted_string.decode('utf-8')
            except Exception as e:
                continue
            
            if string_dec:
                print(f"[*] Decrypted string at {string_enc:#x}: {string_dec}")
                dec_members.append((idx, string_dec))
        
        if dec_members:
            from binaryninja import TypeBuilder
            # Create enumeration using TypeBuilder
            builder = TypeBuilder.enumeration()
            for idx, string_value in dec_members:
                # Use the actual decrypted string as the enum member name with quotes
                # and the index as the hex value
                enum_member_name = f"'{string_value}'"
                builder.append(enum_member_name, idx)
            
            # Define the enumeration type using immutable_copy()
            self.registered_name = self.bv.define_user_type("dec_enum", builder.immutable_copy())
            self.enum_type = self.bv.get_type_by_name(self.registered_name)
            print(f"[*] Created enumeration 'dec_enum' with {len(dec_members)} members")
            
            # Also print the mapping for reference
            print("[*] String index to decrypted string mapping:")
            for idx, string_value in dec_members:
                print(f"    {idx:#x}: '{string_value}'")
                
        self.bv.update_analysis_and_wait()
        
        # Change the type of the first argument in calls to the decryptor function
        # if self.decryptor and self.enum_type:
        #     try:
        #         from binaryninja import Type, FunctionParameter
                
        #         # Get the current function type
        #         func_type = self.decryptor.type
        #         new_func_type = None
                
        #         if func_type and hasattr(func_type, 'parameters') and len(func_type.parameters) > 0:
        #             # Use existing parameters but modify only the first one
        #             new_params = []
        #             for i, param in enumerate(func_type.parameters):
        #                 if i == 0:  # First parameter - change to enum type
        #                     new_param = FunctionParameter(self.enum_type, param.name if param.name else "string_offset")
        #                     new_params.append(new_param)
        #                     print(f"[*] Changed first parameter '{param.name if param.name else 'arg0'}' from {param.type} to dec_enum")
        #                 else:  # All other parameters - keep unchanged
        #                     new_params.append(param)
        #                     print(f"[*] Keeping parameter {i} '{param.name if param.name else f'arg{i}'}' as {param.type}")
                    
        #             # Create new function type with all parameters
        #             new_func_type = Type.function(func_type.return_value, new_params)
        #             print(f"[*] Created new function type with {len(new_params)} parameters")
                    
        #         elif func_type and hasattr(func_type, 'return_value'):
        #             # Function exists but no parameters defined - add our enum as first parameter
        #             new_params = [FunctionParameter(self.enum_type, "string_index")]
        #             new_func_type = Type.function(func_type.return_value, new_params)
        #             print("[*] Added enum parameter to function with no existing parameters")
                    
        #         else:
        #             # No function type - create a basic one with our enum as first parameter
        #             new_params = [FunctionParameter(self.enum_type, "string_index")]
        #             new_func_type = Type.function(Type.void(), new_params)
        #             print("[*] Created new function type with enum parameter")
                
        #         if new_func_type:
        #             # Find all calls to the decryptor function and set their type
        #             call_count = 0
        #             for func in self.bv.functions:
        #                 for addr in func.call_sites:
        #                     call_target = func.get_call_target(addr)
        #                     if call_target == self.decryptor.start:
        #                         # This is a call to our decryptor function
        #                         func.set_call_type_adjustment(addr, new_func_type)
        #                         call_count += 1
        #                         print(f"[*] Set call type adjustment at {addr:#x}")
                    
        #             if call_count > 0:
        #                 print(f"[*] Updated {call_count} calls to decryptor function with enum type")
        #                 # Force analysis update to reflect the changes
        #                 self.bv.update_analysis_and_wait()
        #             else:
        #                 print("[!] No calls to decryptor function found")
        #         else:
        #             print("[!] Failed to create new function type")
                    
        #     except Exception as e:
        #         print(f"[!] Failed to set call type adjustments: {e}")
        #         import traceback
        #         traceback.print_exc()

        
        
        self.bv.update_analysis_and_wait()
        return
    
bv.begin_undo_actions()

ds = DecStr(bv)
ds.Start()


bv.commit_undo_actions()