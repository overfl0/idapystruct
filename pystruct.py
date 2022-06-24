from typing import Iterable

import ida_struct
import ida_typeinf
import idaapi
import idc


if idaapi.inf_is_64bit():
    POINTER_SIZE = 8
else:
    POINTER_SIZE = 4


class HexString(int):
    def __repr__(self):
        return hex(self)


class PyStruct:
    def __init__(self, ea, type_name=None, is_array=False):
        self._ea = HexString(ea)
        self._is_array = is_array

        self._name = self._strip_keywords(type_name)
        if self._name is None:
            self._name = idc.get_type(ea)
        if self._name is None:
            raise ValueError(f"type of PyStruct at {hex(ea)} cannot be None")

        struct_id = idc.get_struc_id(self._name)
        if struct_id == 0xffffffffffffffff:
            raise ValueError(f'Unknown structure type: {self._name}')

        self._struct_def = ida_struct.get_struc(struct_id)
        self._struct_size = idc.get_struc_size(struct_id)

        # Apply type information
        decl = self._name + ('*' if is_array else '') + ';'
        _type = idc.parse_decl(decl, 0)
        idc.apply_type(ea, _type, 0)
        # tif = ida_typeinf.tinfo_t()
        #
        # for member in self.struct_def.members:
        #     member_name = ida_struct.get_member_name(member.id)
        #     if ida_struct.get_member_tinfo(tif, member):
        #         print(member_name, tif.__str__())

    @staticmethod
    def _strip_keywords(name):
        if name is None:
            return None
        # TODO: this is just a workaround. Fixme elsewhere
        if name.startswith('struct '):
            return name[len('struct '):]
        return name

    def _create_class(self, pointer, name, is_array):
        all_classes = self._all_subclasses(PyStruct)
        if name not in all_classes:
            return PyStruct(pointer, type_name=name, is_array=is_array)

        return all_classes[name](pointer, is_array=is_array)

    def __getattr__(self, name):
        if self._is_array:
            return AttributeError(f"'{self._name}*' object has no attribute '{name}'. "
                                  f"Use array notation to access the elements")

        member = ida_struct.get_member_by_name(self._struct_def, name)
        if member is None:
            raise AttributeError(f"'{self._name}' object has no attribute '{name}'")

        tif = ida_typeinf.tinfo_t()

        if not ida_struct.get_member_tinfo(tif, member):
            raise RuntimeError(f"Could not get type info from '{self._name}.{name}'")

        if tif.is_int() or str(tif) in ['_DWORD']:
            return self._get_member_int(member, self._ea + member.soff)

        elif tif.is_pvoid():
            return self._get_member_int(member, self._ea + member.soff)

        elif tif.is_struct():
            pointer = self._ea + member.soff
            name = str(tif)
            return self._create_class(pointer, name, is_array=False)

        elif tif.is_ptr():
            pointer = self._get_member_int(member, self._ea + member.soff)
            if pointer == 0:
                return None

            assert (str(tif).endswith('*'))
            if not tif.remove_ptr_or_array():
                raise ValueError(f'Could not dereference type {str(tif)}')

            # Was this a [const] char *?
            if tif.is_char():
                return idc.get_strlit_contents(pointer, -1, idc.STRTYPE_C)

            # Handle special case if we have an array here
            if not tif.is_ptr_or_array():
                return self._create_class(pointer, str(tif), is_array=False)
            else:
                if not tif.remove_ptr_or_array():
                    raise ValueError(f'Could not dereference type {str(tif)}')
                return self._create_class(pointer, str(tif), is_array=True)

        raise NotImplementedError(f"PyStruct.__getattr__: Type '{str(tif)}' is unsupported")

    def __getitem__(self, key):
        if not isinstance(key, int):
            raise IndexError(f'Invalid index: {key}')

        if key < 0:
            raise IndexError('Negative indexes are not supported')

        if self._is_array:
            item_ea = idaapi.get_qword(self._ea + key * POINTER_SIZE)
            return self._create_class(item_ea, name=self._name, is_array=False)

        return self._create_class(self._ea + key * self._struct_size, name=self._name, is_array=False)

    def __dir__(self) -> Iterable[str]:
        curr = super().__dir__()

        if not self._is_array:
            for member in self._struct_def.members:
                member_name = ida_struct.get_member_name(member.id)
                curr.append(member_name)

        return curr

    def __str__(self):
        name = self._name if not self._is_array else self._name + '*'
        return f'{self.__class__.__name__}<{name} at {hex(self._ea)}>'

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def _all_subclasses(cls):
        classes = set(cls.__subclasses__()).union(
            [s for c in cls.__subclasses__() for s in cls._all_subclasses(c)])
        return {c.__name__: c for c in classes}

    @staticmethod
    def _get_member_int(member: ida_struct.member_t, ea):
        size = member.eoff - member.soff  # noqa

        if size == 0:
            member_name = ida_struct.get_member_name(member.id)
            raise ValueError(f"'{member_name}' size is 0, at {hex(ea)}")

        if size == 1:
            return idaapi.get_byte(ea)
        elif size == 2:
            return idaapi.get_word(ea)
        elif size == 4:
            return idaapi.get_dword(ea)
        elif size == 8:
            return idaapi.get_qword(ea)
        else:
            raise ValueError(f'Fetching ints of size {size} is not yet implemented')
        # elif size == 16:
        #     return idaapi.get_bytes()


'''
p = pystruct.PyStruct(0xDEADBEEF)
h = p.items.data.xdtree
xdtree = h.buckets_D8.data[1]
'''
