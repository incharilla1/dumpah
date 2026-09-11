import win32gui
import win32process
import time
import struct
import math
import re
from memory.api import Memopy
from utils import GetRenderViewFromLog

Window = None
Process = Memopy(0)
FakeDataModelToRealDatamodel = 0x1D0

def pattern_to_regex(pattern_str):
    parts = pattern_str.split()
    regex = b''
    for part in parts:
        regex += b'.' if part == '?' else bytes.fromhex(part)
    return regex

def read_double_unaligned(process, address):
    try:
        b = process.read_bytes(address, 8)
        if b and len(b) == 8:
            return struct.unpack('<d', b)[0]
    except Exception:
        pass
    return None

def scan_pattern(data, pattern):
    plen = len(pattern)
    for i in range(len(data) - plen + 1):
        for j in range(plen):
            if pattern[j] != b'.'[0] and data[i + j] != pattern[j]:
                break
        else:
            return i
    return -1

def find_datamodeldeleterpointer(process, base_address, module_size):
    pattern_str = "48 8D 0D ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 75 ? 48 8B CB E8 ? ? ? ? 48 8D 0D"
    pattern = pattern_to_regex(pattern_str)
    region = base_address
    end = base_address + module_size
    while region < end:
        mbi = process.virtual_query(region)
        if mbi.State != 0x1000 or mbi.Protect not in [0x02, 0x04, 0x20, 0x40]:
            region += mbi.RegionSize
            continue
        current_bytes = process.read_bytes(region, mbi.RegionSize)
        match = re.search(pattern, current_bytes, re.DOTALL)
        if match:
            match_addr = region + match.span()[0]
            rel32_bytes = process.read_bytes(match_addr + 3, 4)
            rel32 = int.from_bytes(rel32_bytes, "little", signed=False)
            return match_addr + 7 + rel32 + 0x10
        region += mbi.RegionSize
    print("datamodeldeleterpointer pattern not found")
    return None

def find_visualenginepointer(process, base_address, module_size):
    pattern_str = "48 89 1D ? ? ? ? 8D 48 ? 48 89 1D ? ? ? ? 48 8D 05 ? ? ? ? 48 89 1D ? ? ? ? 48 89 1D"
    pattern = pattern_to_regex(pattern_str)
    region = base_address
    end = base_address + module_size
    while region < end:
        mbi = process.virtual_query(region)
        if mbi.State != 0x1000 or mbi.Protect not in [0x02, 0x04, 0x20, 0x40]:
            region += mbi.RegionSize
            continue
        current_bytes = process.read_bytes(region, mbi.RegionSize)
        match = re.search(pattern, current_bytes, re.DOTALL)
        if match:
            match_addr = region + match.span()[0]
            rel32_bytes = process.read_bytes(match_addr + 3, 4)
            rel32 = int.from_bytes(rel32_bytes, "little", signed=False)
            return match_addr + 7 + rel32 + 0x18
        region += mbi.RegionSize
    return None

def find_taskschedulerpointer(process, base_address, module_size):
    pattern_str = "48 8B 1D ? ? ? ? EB ? 39 05 ? ? ? ? 7E ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 75 ? B9 ? ? ? ? E8 ? ? ? ? 48 85 C0 74 ? 48 89 44 24 ? 48 8B C8 E8 ? ? ? ? 90 48 89 05 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 1D ? ? ? ? 48 8D 93 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? F2 0F 10 B3 ? ? ? ? 8B 54 24 ? 48 8D 4C 24 ? E8 ? ? ? ? 0F 28 C6 0F 28 74 24 ? 48 83 C4 ? 5B C3 48 8D 4C 24 ? E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 40 53"
    pattern = pattern_to_regex(pattern_str)
    region = base_address
    end = base_address + module_size
    while region < end:
        mbi = process.virtual_query(region)
        if mbi.State != 0x1000 or mbi.Protect not in [0x02, 0x04, 0x20, 0x40]:
            region += mbi.RegionSize
            continue
        current_bytes = process.read_bytes(region, mbi.RegionSize)
        match_offset = scan_pattern(current_bytes, pattern)
        if match_offset != -1:
            match_addr = region + match_offset
            rel32_bytes = process.read_bytes(match_addr + 3, 4)
            rel32 = int.from_bytes(rel32_bytes, "little", signed=False)
            return match_addr + 7 + rel32 + 0x18
        region += mbi.RegionSize
    return None

def fetch_roblox_pid():
    global Window, Process
    waiting_printed = False
    while True:
        Window = win32gui.FindWindow(None, "Roblox")
        if Window:
            break
        if not waiting_printed:
            print("[*] Waiting for Roblox window...")
            waiting_printed = True
        time.sleep(1)
    return win32process.GetWindowThreadProcessId(Window)[1]

def initialize():
    pid = fetch_roblox_pid()
    Process.update_pid(pid)
    if not Process.process_handle:
        return False, -1
    return True, pid

def read_float_unaligned(process, address):
    try:
        b = process.read_bytes(address, 4)
        if b and len(b) == 4:
            return struct.unpack('<f', b)[0]
    except Exception:
        pass
    return None

def read_long_unaligned(process, address):
    try:
        b = process.read_bytes(address, 4)
        if b and len(b) == 4:
            return struct.unpack('<I', b)[0], struct.unpack('<i', b)[0]
    except Exception:
        pass
    return None, None

def read_longlong_unaligned(process, address):
    try:
        b = process.read_bytes(address, 8)
        if b and len(b) == 8:
            return struct.unpack('<Q', b)[0], struct.unpack('<q', b)[0]
    except Exception:
        pass
    return None, None

def find_fakedatamodelpointer(process, base_address, module_size):
    pattern_str = "48 8D 0D ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 75 ? 48 8B CB E8 ? ? ? ? 48 8D 0D"
    pattern = pattern_to_regex(pattern_str)
    region = base_address
    end = base_address + module_size
    while region < end:
        mbi = process.virtual_query(region)
        if mbi.State != 0x1000 or mbi.Protect not in [0x02, 0x04, 0x20, 0x40]:
            region += mbi.RegionSize
            continue
        current_bytes = process.read_bytes(region, mbi.RegionSize)
        match = re.search(pattern, current_bytes, re.DOTALL)
        if match:
            match_addr = region + match.span()[0]
            rel32_bytes = process.read_bytes(match_addr + 3, 4)
            rel32 = int.from_bytes(rel32_bytes, "little", signed=False)
            return match_addr + 7 + rel32 + 0x18
        region += mbi.RegionSize
    print("FakeDataModelPointer pattern not found")
    return None

def wait_for_value(getter, print_wait, print_fail, max_attempts=30, delay=1):
    attempts = 0
    while attempts < max_attempts:
        value = getter()
        if value:
            return value
        print(print_wait)
        time.sleep(delay)
        attempts += 1
    print(print_fail)
    return None

def main():
    inline_outputs = []
    print("[+] Finding Roblox...")
    success, pid = initialize()
    if not success:
        print("[+] Couldn't find Roblox")
        return

    print(f"[+] Found Roblox: {pid}")
    time.sleep(1.5)
    print("[+] Getting DataModel...")

    base_address = wait_for_value(
        lambda: Process.get_module_base("RobloxPlayerBeta.exe"),
        "[-] Waiting for Roblox base address...",
        "[-] Failed to get Roblox base address."
    )
    if not base_address:
        return
    print(f"[+] Base Address: 0x{base_address:X}")

    module_size = wait_for_value(
        lambda: Process.get_module_size("RobloxPlayerBeta.exe"),
        "[-] Waiting for Roblox module size...",
        "[-] Failed to get Roblox module size."
    )
    if not module_size:
        return
    print(f"[+] Module Size: 0x{module_size:X}")

    visualengine_addr = find_visualenginepointer(Process, base_address, module_size)
    if visualengine_addr:
        inline_outputs.append(f"    inline constexpr uintptr_t VisualEnginePointer = 0x{visualengine_addr - base_address:X};")
    else:
        inline_outputs.append("[-] Could not find VisualEnginePointer offset. Try Restarting the game and running this script before it launches.")

    datamodeldeleter_addr = find_datamodeldeleterpointer(Process, base_address, module_size)
    if datamodeldeleter_addr:
        inline_outputs.append(f"    inline constexpr uintptr_t DataModelDeleterPointer = 0x{datamodeldeleter_addr - base_address:X};")
    else:
        inline_outputs.append("[-] Could not find DataModelDeleterPointer offset.")

    taskscheduler_addr = find_taskschedulerpointer(Process, base_address, module_size)
    if taskscheduler_addr:
        inline_outputs.append(f"    inline constexpr uintptr_t TaskSchedulerPointer = 0x{taskscheduler_addr - base_address:X};")
    else:
        inline_outputs.append("[-] Could not find TaskSchedulerPointer offset.")

    RenderView = GetRenderViewFromLog()

    fakedatamodel_addr = wait_for_value(
        lambda: find_fakedatamodelpointer(Process, base_address, module_size),
        "[*] Waiting for valid FakeDataModelPointer...",
        "[-] Failed to get FakeDataModelPointer."
    )
    if not fakedatamodel_addr:
        return

    fakedatamodel_offset = fakedatamodel_addr - base_address
    fake_dm_ptr = Process.read_longlong(base_address + fakedatamodel_offset)

    def get_datamodel():
        for i in range(0, 0x1000, 8):
            candidate = Process.read_longlong(fake_dm_ptr + i)
            if candidate and candidate > 0x10000:
                for name_off in range(0x1, 0x1000):
                    ptr = Process.read_longlong(candidate + name_off)
                    instance_name = Process.read_string(ptr)
                    if instance_name in ("Ugc", "LuaApp"):
                        return candidate, i
        return None

    attempts = 0
    datamodel = None
    fakedatamodeltodatamodel_offset = None
    while attempts < 30:
        result = get_datamodel()
        if result:
            datamodel, fakedatamodeltodatamodel_offset = result
            break
        print("[*] Waiting for valid DataModel pointer...")
        time.sleep(1)
        attempts += 1
    if datamodel is None:
        print("[-] Failed to get DataModel pointer.")
        return

    print(f"[+] Found DataModel: 0x{datamodel:X}")
    inline_outputs.append(f"    inline constexpr uintptr_t FakeDataModelPointer = 0x{fakedatamodel_offset:X};")
    inline_outputs.append(f"    inline constexpr uintptr_t FakeDataModelToDataModel = 0x{fakedatamodeltodatamodel_offset:X};")

    if RenderView:
        inline_outputs.append(f"    inline constexpr uintptr_t VisualEngine = 0x{RenderView + 0x10 - RenderView:X};")
    else:
        inline_outputs.append("[-] Could not get RenderView from log. Trying restarting your game.")

    time.sleep(1)
    print("\n[+] Dumping...\n")
    time.sleep(2)

    for line in inline_outputs:
        print(line)

    name_offset = 0x1
    workspace_offset = 0x1
    parent_offset = 0x1
    children_offset = 0x1
    class_descriptor_offset = 0x1
    players_address = 0x1
    localplayer_offset = 0x1
    modelinstance_offset = 0x1
    placeid_offset = 0x1

    REAL_PLAYER_NAME = "HappyPotato162"
    PLACE_ID = 76671211968229
    USER_ID = 1234567890
    EXPECTED_CREATORID = 3350788556
    MAX_OFFSET = 0x1000

    EXPECTED_HEALTH = 16122345.0
    EXPECTED_MAXHEALTH = 1512312320.0
    EXPECTED_HIPHEIGHT = 2.0
    EXPECTED_STATEID = 0
    EXPECTED_GRAVITY = 196.2
    EXPECTED_WALKSPEED = 16.0
    EXPECTED_JUMPPOWER = 50.0
    EPSILON = 0.5
    max_fov_offset = 0x4000

    while name_offset < MAX_OFFSET:
        ptr = Process.read_longlong(datamodel + name_offset)
        instance_name = Process.read_string(ptr)
        if instance_name in ("Ugc", "LuaApp"):
            print(f"    inline constexpr uintptr_t Name = {hex(name_offset)};")
            break
        name_offset += 1
    else:
        print("[-] Failed to find 'Ugc' or 'LuaApp' instance name")
        return

    while True:
        placeid = Process.read_longlong(datamodel + placeid_offset)
        if placeid == PLACE_ID:
            print(f"    inline constexpr uintptr_t PlaceId = {hex(placeid_offset)};")
            print(f"    inline constexpr uintptr_t GameId = {hex(placeid_offset - 0x8)};")
            break
        placeid_offset += 1

    while True:
        workspace_ptr = Process.read_longlong(datamodel + workspace_offset)
        name_ptrr = Process.read_longlong(workspace_ptr + name_offset)
        if Process.read_string(name_ptrr) == "Workspace":
            print(f"    inline constexpr uintptr_t Workspace = {hex(workspace_offset)};")
            break
        workspace_offset += 1

    while True:
        parent_ptr = Process.read_longlong(workspace_ptr + parent_offset)
        name_ptrrr = Process.read_longlong(parent_ptr + name_offset)
        if Process.read_string(name_ptrrr) == "Ugc":
            print(f"    inline constexpr uintptr_t Parent = {hex(parent_offset)};")
            break
        parent_offset += 1

    while True:
        class_descriptor_ptr = Process.read_longlong(datamodel + class_descriptor_offset)
        name_off = 0
        classname = ""
        while name_off < 0x40:
            classname_ptr = Process.read_longlong(class_descriptor_ptr + name_off)
            classname = Process.read_string(classname_ptr)
            if classname == "DataModel":
                print(f"    inline constexpr uintptr_t ClassDescriptor = {hex(class_descriptor_offset)};")
                print(f"    inline constexpr uintptr_t ClassDescriptorToClassName = {hex(name_off)};")
                break
            name_off += 8
        if classname == "DataModel":
            break
        class_descriptor_offset += 1

    container = []
    Process.suspend()
    while True:
        start = Process.read_longlong(datamodel + children_offset)
        instances = Process.read_longlong(start)
        f = 0
        found = False
        while f != 30:
            container.append(Process.read_longlong(instances))
            instances += 16
            f += 1
        for maybe_child_of_instance in container:
            name_ptr = Process.read_longlong(maybe_child_of_instance + name_offset)
            if Process.read_string(name_ptr) == "Players":
                print(f"    inline constexpr uintptr_t Children = {hex(children_offset)};")
                players_address = maybe_child_of_instance
                found = True
        if found:
            break
        children_offset += 1
        container.clear()
    Process.resume()

    Process.suspend()
    while True:
        localplayer_ptr = Process.read_longlong(players_address + localplayer_offset)
        name_sigma = Process.read_longlong(localplayer_ptr + name_offset)
        if localplayer_offset > 0x1000:
            print("[-] LocalPlayer: failed")
            break
        if Process.read_string(name_sigma) == REAL_PLAYER_NAME:
            print(f"    inline constexpr uintptr_t LocalPlayer = {hex(localplayer_offset)};")
            break
        localplayer_offset += 1
    Process.resume()

    while True:
        possible_char = Process.read_longlong(localplayer_ptr + modelinstance_offset)
        possible_char_class_descriptor = Process.read_longlong(possible_char + class_descriptor_offset)
        possible_char_class_descriptor_name = Process.read_string(Process.read_longlong(possible_char_class_descriptor + 0x8))
        if modelinstance_offset > 0x1000:
            print("[-] ModelInstance: failed")
            break
        if possible_char_class_descriptor_name == "Model":
            print(f"    inline constexpr uintptr_t ModelInstance = {hex(modelinstance_offset)};")
            break
        modelinstance_offset += 1

    baseplate_ptr = None
    baseplate_children_offset = 0x1
    container = []
    Process.suspend()
    while baseplate_children_offset < 0x1000:
        start = Process.read_longlong(workspace_ptr + baseplate_children_offset)
        if not start or start < 0x10000:
            baseplate_children_offset += 1
            continue
        instances = Process.read_longlong(start)
        f = 0
        found = False
        while f != 30:
            instance_ptr = Process.read_longlong(instances)
            if instance_ptr and instance_ptr > 0x10000:
                container.append(instance_ptr)
            instances += 16
            f += 1
        for maybe_baseplate in container:
            name_ptr = Process.read_longlong(maybe_baseplate + name_offset)
            if name_ptr and name_ptr > 0x10000 and Process.read_string(name_ptr) == "Baseplate":
                baseplate_ptr = maybe_baseplate
                found = True
                break
        if found:
            break
        baseplate_children_offset += 1
        container.clear()
    Process.resume()

    customvalue_ptr = None
    customvalue_children_offset = 0x1
    container = []
    Process.suspend()
    while customvalue_children_offset < 0x1000:
        start = Process.read_longlong(baseplate_ptr + customvalue_children_offset)
        if not start or start < 0x10000:
            customvalue_children_offset += 1
            continue
        instances = Process.read_longlong(start)
        f = 0
        found = False
        while f != 30:
            instance_ptr = Process.read_longlong(instances)
            if instance_ptr and instance_ptr > 0x10000:
                container.append(instance_ptr)
            instances += 16
            f += 1
        for maybe_child in container:
            name_ptr = Process.read_longlong(maybe_child + name_offset)
            if name_ptr and name_ptr > 0x10000 and Process.read_string(name_ptr) == "CustomValue":
                customvalue_ptr = maybe_child
                found = True
                break
        if found:
            break
        customvalue_children_offset += 1
        container.clear()
    Process.resume()

    basepart_ptr = None
    basepart_children_offset = 0x1
    container = []
    Process.suspend()
    while basepart_children_offset < 0x1000:
        start = Process.read_longlong(workspace_ptr + basepart_children_offset)
        if not start or start < 0x10000:
            basepart_children_offset += 1
            continue
        instances = Process.read_longlong(start)
        f = 0
        found = False
        while f != 30:
            instance_ptr = Process.read_longlong(instances)
            if instance_ptr and instance_ptr > 0x10000:
                container.append(instance_ptr)
            instances += 16
            f += 1
        for maybe_basepart in container:
            name_ptr = Process.read_longlong(maybe_basepart + name_offset)
            if name_ptr and name_ptr > 0x10000 and Process.read_string(name_ptr) == "BasePart":
                basepart_ptr = maybe_basepart
                found = True
                break
        if found:
            break
        basepart_children_offset += 1
        container.clear()
    Process.resume()

    if customvalue_ptr and customvalue_ptr > 0x10000:
        found_value = False
        for offset in range(0, 0x200, 4):
            unsigned, signed = read_long_unaligned(Process, customvalue_ptr + offset)
            if unsigned == 125126511 or signed == 125126511:
                print(f"    inline constexpr uintptr_t Value = 0x{offset:x};")
                found_value = True
                break
        if not found_value:
            print("[-] Could not find Value in CustomValue.")
    else:
        print("[-] CustomValue not found as child of Baseplate.")

    camera_offset = 0
    MAX_CAMERA_OFFSET = 0x1000
    camera_ptr = None
    while camera_offset < MAX_CAMERA_OFFSET:
        camera_ptr = Process.read_longlong(workspace_ptr + camera_offset)
        if camera_ptr and camera_ptr > 0x10000:
            try:
                class_descriptor_ptr = Process.read_longlong(camera_ptr + 0x18)
                class_name_ptr = Process.read_longlong(class_descriptor_ptr + 0x8)
                if Process.read_string(class_name_ptr) == "Camera":
                    print(f"    inline constexpr uintptr_t Camera = 0x{camera_offset:x};")
                    break
            except Exception:
                pass
        camera_offset += 8
    else:
        print("[-] Camera not found in Workspace")

    EXPECTED_POS = (0.0, 104.518, 12.5)
    found_pos = False
    camera_pos_offset = None
    for offset in range(0, 0x400, 4):
        x = Process.read_float(camera_ptr + offset)
        y = Process.read_float(camera_ptr + offset + 4)
        z = Process.read_float(camera_ptr + offset + 8)
        if (x is not None and y is not None and z is not None and
            abs(x - EXPECTED_POS[0]) < EPSILON and
            abs(y - EXPECTED_POS[1]) < EPSILON and
            abs(z - EXPECTED_POS[2]) < EPSILON):
            print(f"    inline constexpr uintptr_t CameraPos = 0x{offset:x};")
            found_pos = True
            camera_pos_offset = offset
            break
    if not found_pos:
        print("CameraPos: not found in scanned range.")
    else:
        print(f"    inline constexpr uintptr_t CameraRotation = 0x{camera_pos_offset - 0x24:x};")
        for offset in range(0, 0x400, 8):
            ptr = Process.read_longlong(camera_ptr + offset)
            if ptr and ptr > 0x10000:
                try:
                    class_desc = Process.read_longlong(ptr + 0x18)
                    class_name_ptr = Process.read_longlong(class_desc + 0x8)
                    if Process.read_string(class_name_ptr) in ["Humanoid", "Part", "Model"]:
                        print(f"    inline constexpr uintptr_t CameraSubject = 0x{offset:x};")
                        break
                except Exception:
                    continue

    if 'workspace_ptr' in locals() and workspace_ptr and workspace_ptr > 0x10000:
        found = False
        for offset in range(0, 0x1200):
            val = read_float_unaligned(Process, workspace_ptr + offset)
            if val is not None and abs(val - EXPECTED_GRAVITY) < EPSILON:
                print(f"    inline constexpr uintptr_t Gravity = 0x{offset:x};")
                found = True
                break
        if not found:
            print("Gravity: not found in scanned range.")

    if 'localplayer_ptr' in locals() and localplayer_ptr and localplayer_ptr > 0x10000:
        found = False
        for offset in range(0, 0x1200, 8):
            unsigned, signed = read_longlong_unaligned(Process, localplayer_ptr + offset)
            if unsigned is not None and (unsigned == USER_ID or signed == USER_ID or signed == USER_ID - 2**64):
                print(f"    inline constexpr uintptr_t UserId = 0x{offset:x};")
                found = True
                break
        if not found:
            print(f"UserId {USER_ID} not found in scanned range.")

    if 'camera_ptr' in locals() and camera_ptr and camera_ptr > 0x10000:
        found = False
        for offset in range(0, max_fov_offset, 4):
            val = read_float_unaligned(Process, camera_ptr + offset)
            if val is not None and 0.5 < val < 2.5:
                deg = math.degrees(val)
                if 60 <= deg <= 120:
                    print(f"    inline constexpr uintptr_t FOV = 0x{offset:x};")
                    found = True
                    break
        if not found:
            print("FOV: not found in scanned range.")

    if 'localplayer_ptr' in locals() and localplayer_ptr and localplayer_ptr > 0x10000:
        found = False
        for offset in range(0, 0x1200, 8):
            ptr = Process.read_longlong(localplayer_ptr + offset)
            if ptr and ptr > 0x10000:
                try:
                    class_desc = Process.read_longlong(ptr + class_descriptor_offset)
                    class_name_ptr = Process.read_longlong(class_desc + 0x8)
                    if Process.read_string(class_name_ptr) == "Team":
                        print(f"    inline constexpr uintptr_t Team = 0x{offset:x};")
                        found = True
                except Exception:
                    continue
        if not found:
            print("Team not found in scanned range.")

    team_ptr = None
    for offset in range(0, 0x1200, 8):
        ptr = Process.read_longlong(localplayer_ptr + offset)
        if ptr and ptr > 0x10000:
            try:
                class_desc = Process.read_longlong(ptr + class_descriptor_offset)
                class_name_ptr = Process.read_longlong(class_desc + 0x8)
                if Process.read_string(class_name_ptr) == "Team":
                    team_ptr = ptr
                    break
            except Exception:
                continue

    if team_ptr:
        found_teamcolor_id = False
        for offset in range(0, 0x100, 4):
            unsigned, signed = read_long_unaligned(Process, team_ptr + offset)
            if unsigned == 23 or signed == 23:
                print(f"    inline constexpr uintptr_t TeamColor = 0x{offset:x};")
                found_teamcolor_id = True
                break
        if not found_teamcolor_id:
            print("[-] TeamColor not found in Team instance memory.")

    found = False
    for offset in range(0, 0x400, 8):
        unsigned, signed = read_longlong_unaligned(Process, datamodel + offset)
        if unsigned == EXPECTED_CREATORID or signed == EXPECTED_CREATORID:
            print(f"    inline constexpr uintptr_t CreatorId = 0x{offset:x};")
            found = True
            break
    if not found:
        print("[-] Failed to find CreatorId offset")

    humanoid_ptr = None
    if 'possible_char' in locals() and possible_char and possible_char > 0x10000:
        char_children_offset = 0x1
        container = []
        Process.suspend()
        while char_children_offset < 0x1000:
            start = Process.read_longlong(possible_char + char_children_offset)
            if not start or start < 0x10000:
                char_children_offset += 1
                continue
            instances = Process.read_longlong(start)
            f = 0
            found = False
            while f != 30:
                instance_ptr = Process.read_longlong(instances)
                if instance_ptr and instance_ptr > 0x10000:
                    container.append(instance_ptr)
                instances += 16
                f += 1
            for maybe_humanoid in container:
                name_ptr = Process.read_longlong(maybe_humanoid + name_offset)
                if name_ptr and name_ptr > 0x10000 and Process.read_string(name_ptr) == "Humanoid":
                    humanoid_ptr = maybe_humanoid
                    found = True
                    break
            if found:
                break
            char_children_offset += 1
            container.clear()
        Process.resume()

    if humanoid_ptr:
        for offset in range(0, 0x400, 4):
            val = read_float_unaligned(Process, humanoid_ptr + offset)
            if val is not None and abs(val - EXPECTED_HEALTH) < EPSILON:
                print(f"    inline constexpr uintptr_t Health = 0x{offset:x};")
                break

        for offset in range(0, 0x400, 4):
            val = read_float_unaligned(Process, humanoid_ptr + offset)
            if val is not None and abs(val - EXPECTED_MAXHEALTH) < EPSILON:
                print(f"    inline constexpr uintptr_t MaxHealth = 0x{offset:x};")
                break

        for offset in range(0, 0x400, 4):
            val = read_float_unaligned(Process, humanoid_ptr + offset)
            if val is not None and abs(val - EXPECTED_HIPHEIGHT) < EPSILON:
                print(f"    inline constexpr uintptr_t HipHeight = 0x{offset:x};")
                break

        for offset in range(0, 0x100, 4):
            unsigned, signed = read_long_unaligned(Process, humanoid_ptr + offset)
            if unsigned == EXPECTED_STATEID or signed == EXPECTED_STATEID:
                print(f"    inline constexpr uintptr_t HumanoidStateId = 0x{offset:x};")
                break
    else:
        print("[-] Humanoid not found")

    if humanoid_ptr:
        found_jumppower = False
        for offset in range(0, 0x800, 4):
            val = read_float_unaligned(Process, humanoid_ptr + offset)
            if val is not None and abs(val - EXPECTED_JUMPPOWER) < EPSILON:
                print(f"    inline constexpr uintptr_t JumpPower = 0x{offset:x};")
                found_jumppower = True
                break
        if not found_jumppower:
            print("JumpPower: not found in scanned range.")

        walkspeed_count = 0
        for offset in range(0, 0x800, 4):
            val = read_float_unaligned(Process, humanoid_ptr + offset)
            if val is not None and abs(val - EXPECTED_WALKSPEED) < EPSILON:
                walkspeed_count += 1
                if walkspeed_count == 1:
                    print(f"    inline constexpr uintptr_t WalkSpeed = 0x{offset:x};")
                elif walkspeed_count == 2:
                    print(f"    inline constexpr uintptr_t WalkSpeedCheck = 0x{offset:x};")
                    break
        if walkspeed_count == 0:
            print("WalkSpeed: not found in scanned range.")

    found_primitive = False
    primitive_offset = None
    ptr = None
    if baseplate_ptr:
        for offset in range(0, 0x400, 8):
            ptr = Process.read_longlong(baseplate_ptr + offset)
            if ptr and ptr > 0x10000 and offset > 0x150:
                print(f"    inline constexpr uintptr_t Primitive = 0x{offset:x};")
                found_primitive = True
                primitive_offset = offset
                break
        if not found_primitive:
            print("[-] Primitive offset not found in Baseplate.")

    basepart_primitive_ptr = None
    if basepart_ptr and found_primitive and primitive_offset is not None:
        basepart_primitive_ptr = Process.read_longlong(basepart_ptr + primitive_offset)

    if basepart_primitive_ptr and basepart_primitive_ptr > 0x10000:
        found_position = False
        EXPECTED_X = -106
        EXPECTED_Y = 813
        EXPECTED_Z = 412
        for pos_off in range(0, 0x1000, 4):
            x = read_float_unaligned(Process, basepart_primitive_ptr + pos_off)
            y = read_float_unaligned(Process, basepart_primitive_ptr + pos_off + 4)
            z = read_float_unaligned(Process, basepart_primitive_ptr + pos_off + 8)
            if (x is not None and y is not None and z is not None and
                abs(x - EXPECTED_X) < EPSILON and
                abs(y - EXPECTED_Y) < EPSILON and
                abs(z - EXPECTED_Z) < EPSILON):
                print(f"    inline constexpr uintptr_t Position = 0x{pos_off:x};")
                found_position = True
                break
        if not found_position:
            print("[-] Could not find BasePart position in Primitive.")
            print("[-] Could not find Baseplate position in Primitive.")

            ondemand_offset = None
            for offset in range(0x20, 0x50, 8):
                candidate = Process.read_longlong(ptr + offset)
                if candidate and candidate > 0x10000:
                    ondemand_offset = offset
                    print(f"    inline constexpr uintptr_t OnDemandInstance = 0x{ondemand_offset:x};")
                    break
            if ondemand_offset is None:
                print("[-] OnDemandInstance pointer not found in Primitive.")
    else:
        print("[-] Baseplate not found, cannot dump Position/Primitive offsets.")

    if datamodel and datamodel > 0x10000:
        found_jobid = False
        for offset in range(0, 0x400, 8):
            ptr = Process.read_longlong(datamodel + offset)
            if ptr and ptr > 0x10000:
                try:
                    s = Process.read_string(ptr)
                    if s and len(s) == 36 and '-' in s:
                        print(f"    inline constexpr uintptr_t JobId = 0x{offset:x};")
                        found_jobid = True
                        break
                except Exception:
                    continue
        if not found_jobid:
            print("[-] JobId not found in DataModel.")

    if humanoid_ptr and humanoid_ptr > 0x10000:
        EXPECTED_MOVE_X = 0.485
        EXPECTED_MOVE_Y = 0.115
        EXPECTED_MOVE_Z = 0.867

        found_move_dir = False
        for offset in range(0, 0x2000, 4):
            x = read_float_unaligned(Process, humanoid_ptr + offset)
            y = read_float_unaligned(Process, humanoid_ptr + offset + 4)
            z = read_float_unaligned(Process, humanoid_ptr + offset + 8)
            if (x is not None and y is not None and z is not None and
                abs(x - EXPECTED_MOVE_X) < EPSILON and
                abs(y - EXPECTED_MOVE_Y) < EPSILON and
                abs(z - EXPECTED_MOVE_Z) < EPSILON):
                print(f"    inline constexpr uintptr_t MoveDirection = 0x{offset:x};")
                found_move_dir = True
                break
        if not found_move_dir:
            print("MoveDirection: not found in scanned range.")
    else:
        print("[-] Humanoid pointer invalid or not found")

    if customvalue_ptr and customvalue_ptr > 0x10000:
        for offset in range(0, 0x500, 4):
            unsigned, signed = read_long_unaligned(Process, customvalue_ptr + offset)
            if unsigned == 125126511 or signed == 125126511:
                print(f"    inline constexpr uintptr_t Value = 0x{offset:x};")
                break

    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()