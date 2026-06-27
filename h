-- anti_env_logger.lua (для загрузки через loadstring)

local ANTI_VERSION = "2.0"

local orig_getfenv = getfenv
local orig_setfenv = setfenv
local orig_debug = debug
local orig_getmetatable = getmetatable
local orig_setmetatable = setmetatable
local orig_error = error
local orig_pcall = pcall
local orig_print = print
local orig_type = type
local orig_pairs = pairs
local orig_rawget = rawget
local orig_rawset = rawset

local CONFIG = {
    mode = "crash",
    block_getfenv = true,
    block_setfenv = true,
    block_debug = true,
    fake_env_size = 3,
    crash_code = 1,
}

local function silent_crash()
    if os and os.exit then
        os.exit(CONFIG.crash_code)
    end
    while true do end
end

local function create_fake_env()
    local fake = {
        _FAKE = true,
        _VERSION = "Lua 5.1",
        print = function() end,
        error = function() end,
        pcall = function() return true end,
        xpcall = function() return true end,
        load = function() return function() end end,
        loadstring = function() return function() end end,
        dofile = function() end,
        require = function() return {} end,
        getfenv = function() return {} end,
        setfenv = function() end,
        debug = nil,
        io = nil,
        os = { exit = function() end },
        string = {},
        table = {},
        math = {},
        coroutine = {},
        _G = nil,
        _ENV = nil,
    }
    fake._G = fake
    fake._ENV = fake
    return fake
end

local function setup_getfenv_trap()
    _G.getfenv = function(f)
        if CONFIG.mode == "crash" then
            silent_crash()
        elseif CONFIG.mode == "fake" then
            return create_fake_env()
        elseif CONFIG.mode == "silent" then
            return {}
        end
        return {}
    end
    
    if orig_debug and type(orig_debug) == "table" then
        orig_debug.getfenv = function(f)
            if CONFIG.mode == "crash" then
                silent_crash()
            elseif CONFIG.mode == "fake" then
                return create_fake_env()
            end
            return {}
        end
    end
end

local function setup_setfenv_trap()
    _G.setfenv = function(f, env)
        return f
    end
    
    if orig_debug and type(orig_debug) == "table" then
        orig_debug.setfenv = function(f, env)
            return f
        end
    end
end

local function clear_all_debug_hooks()
    if orig_debug then
        pcall(function() orig_debug.sethook() end)
        pcall(function() orig_debug.setlocal() end)
        pcall(function() orig_debug.setupvalue() end)
    end
end

local function block_debug_library()
    if orig_debug and type(orig_debug) == "table" then
        for k, v in orig_pairs(orig_debug) do
            if orig_type(v) == "function" then
                orig_debug[k] = function() return nil end
            end
        end
    end
    _G.debug = nil
end

local function protect_metatables()
    _G.getmetatable = function(t)
        local mt = orig_getmetatable(t)
        if mt and mt.__metatable == "locked" then
            return "locked"
        end
        if orig_type(t) == "table" then
            local size = 0
            for _ in orig_pairs(t) do size = size + 1 end
            if size > 10 then
                return "locked"
            end
        end
        return mt
    end
    
    _G.setmetatable = function(t, mt)
        if t == _G or t == _ENV then
            return t
        end
        return orig_setmetatable(t, mt)
    end
end

local function scan_for_threats()
    local threats = {}
    
    if _G.getfenv ~= orig_getfenv then
        threats[#threats + 1] = "getfenv_replaced"
    end
    
    if _G.setfenv ~= orig_setfenv then
        threats[#threats + 1] = "setfenv_replaced"
    end
    
    if _G.debug and orig_type(_G.debug) == "table" then
        local has_funcs = false
        for k, v in orig_pairs(_G.debug) do
            if orig_type(v) == "function" then
                has_funcs = true
                break
            end
        end
        if has_funcs then
            threats[#threats + 1] = "debug_available"
        end
    end
    
    local globals_count = 0
    local suspicious = {"hook", "trace", "spy", "log", "dump", "inspect", "sniff"}
    for k, v in orig_pairs(_G) do
        globals_count = globals_count + 1
        local k_lower = tostring(k):lower()
        for _, s in ipairs(suspicious) do
            if k_lower:find(s) then
                threats[#threats + 1] = "suspicious_global:" .. tostring(k)
                break
            end
        end
    end
    
    if globals_count > 300 then
        threats[#threats + 1] = "too_many_globals:" .. globals_count
    end
    
    if orig_debug and orig_debug.gethook then
        local hook = orig_debug.gethook()
        if hook then
            threats[#threats + 1] = "active_debug_hook"
        end
    end
    
    return threats
end

local function wrap_function(func, name)
    name = name or "anonymous"
    
    return function(...)
        local threats = scan_for_threats()
        if #threats > 0 then
            if CONFIG.mode == "crash" then
                silent_crash()
            end
        end
        
        clear_all_debug_hooks()
        local results = { func(...) }
        clear_all_debug_hooks()
        
        return unpack(results, 1, #results)
    end
end

local function safe_execute(code, env)
    local safe_env = env or {}
    safe_env._G = safe_env
    safe_env._ENV = safe_env
    safe_env.getfenv = function() return create_fake_env() end
    safe_env.setfenv = function() end
    safe_env.debug = nil
    
    local chunk, err = loadstring(code)
    if not chunk then
        return nil, err
    end
    
    if setfenv then
        setfenv(chunk, safe_env)
    end
    
    return orig_pcall(chunk)
end

local function init(options)
    if options then
        for k, v in orig_pairs(options) do
            CONFIG[k] = v
        end
    end
    
    clear_all_debug_hooks()
    
    if CONFIG.block_getfenv then
        setup_getfenv_trap()
    end
    
    if CONFIG.block_setfenv then
        setup_setfenv_trap()
    end
    
    if CONFIG.block_debug then
        block_debug_library()
    end
    
    protect_metatables()
    
    local threats = scan_for_threats()
    
    if #threats > 0 and CONFIG.mode == "crash" then
        silent_crash()
    end
    
    return {
        initialized = true,
        mode = CONFIG.mode,
        threats_found = threats,
        version = ANTI_VERSION,
    }
end

local function destroy()
    _G.getfenv = orig_getfenv
    _G.setfenv = orig_setfenv
    _G.debug = orig_debug
    _G.getmetatable = orig_getmetatable
    _G.setmetatable = orig_setmetatable
    return true
end

-- ВАЖНО: возвращаем модуль
return {
    init = init,
    destroy = destroy,
    wrap = wrap_function,
    scan = scan_for_threats,
    safe_execute = safe_execute,
    clear_hooks = clear_all_debug_hooks,
    fake_env = create_fake_env,
    crash = silent_crash,
    version = ANTI_VERSION,
    config = CONFIG,
}
