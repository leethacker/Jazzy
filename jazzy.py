import re
import subprocess
import sys

debugerr = False

output = ''
dataoutput = ''
dolnout = False
ln = 1
funcpref = 'func_'
stk = []
globalvars = {}
globalarrays = {}

funcs = {}
class function:
    def __init__(self, name, args):
        self.name = name
        self.args = args

def tokenize(s):
    s = re.sub(r'#.*\n', '\n', s)
    mcs = r';;|\*\*|\^/|%32|\*~|>\||<\||>>=|\\<|\.\.\.|\\>|::|<<|>>|!!|!:|==|!=|<=|>='
    r = mcs + r'|\+~|i~|%>|\$\$|`[a-zA-Z0-9_]+|\'[^\']\'|"[^"]*"|\$ *\{[^\}]*}|\$[^\n]*|[@`]?[_a-zA-Z]+|\-?[0-9]+|%[_a-zA-Z0-9]+|\n[^\S\n]*|\S'
    result = ['\n'] + re.findall(r, s)[::-1]
    result = [s if s[0] != '`' else s[1:] for s in result]
    return result    

def out(s):
    global output
    output += ' ' * 4 + s + '\n'

def outlabel(s):
    global output
    output += s + ':\n'

def err(s):
    global ln
    s = s.replace('\n', 'line break')
    #s = s.replace(startblock, 'new block')
    #s = s.replace(endblock, 'end block')
    i = -1
    t = tokens[i]
    while len(t) > 1 and t[0] == '\n':
        i -= 1
        ln += 1
        t = tokens[i]
    print("Error at line {}: {}".format(ln, s))
    if debugerr : int('a')
    sys.exit(0)

def expect(e, f):
    err("expected '{}' found '{}'".format(e, f))
    
def match(s):
    t = getok()
    if t != s : expect(s, t)

namei = 0
def newname(s):
    global namei
    result = '@{}{}'.format(s, namei)
    namei += 1
    return result

lasttoklen = 0
def getok(raw = False):
    global ln
    global lasttoklen
    try:
        t = tokens.pop()
        while not raw and len(t) > 1 and t[0] == '\n':
            ln += 1
            t = getok()
        if t == '\n':
            if len(tokens) != lasttoklen : ln += 1
            lasttoklen = len(tokens)
            #if ln == 30 : int('a')
            if dolnout:
                lnout = ";line {}".format(ln)
                out(lnout)
            #out("incrline")
        return t
    except IndexError as e : err("unexpected end of file")

def getokraw():
    return getok(raw=True)
    
def toptok():
    try:
        i = -1
        t = tokens[i]
        while len(t) > 1 and t[0] == '\n':        
            i -= 1
            t = tokens[i]
        return t
    except : err("unexpected end of file")

def isint(s):
    try:
        int(s)
        return True
    except : return False

def isalnum(s):
    return not isint(s) and s.replace('_', '').isalnum()

def isalint(s) : return isalnum(s) or isint(s)

localvars = {}
def useid(s):
    if s in localvars.keys():
        err("duplicate identifier '{}'".format(s))
    if not isalnum(s):
        expect('valid identifier', s)

def getid():
    s = getok()
    useid(s)
    return s
    
def getint():
    s = getok()
    if s[0] == "'" : return str(ord(s[1:-1]))
    if not isint(s) : expect('int', s)
    return s

def getvar():
    s = expr()
    if len(s) > 1 and s[0] == '%' : return s
    if not s in localvars.keys() : expect('var', s)
    return s

def getreg():
    s = expr() 
    if len(s) > 1 and s[0] == '%' : return s
    if not s in localvars.keys() and not s == retvar : expect('var', s)
    return s

def varloc(s):
    if s == None : err('not a valid value')
    if s[0] == "'" : return ord(s[1:-1])
    elif len(s) > 1 and s[0] == '%':
        r = s[1:]
        if not r in completereglist : err("no such register ''".format(r))
        return r
    elif s in stk : return 'qword [rsp + {}]'.format(stk[::-1].index(s) * 8)
    elif s in localvars.keys() : return localvars[s]
    elif isint(s) : return s
    elif s == '@retvar' : return retreg
    else : err("could not find var '{}'".format(s))
    

def push(s):
    out('push {}'.format(varloc(s)))
    stk.append(s)

regs64 = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12',
        'r13', 'r14']
retreg64 = 'r15'

regs32 = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi']
retreg32 = 'ebp'

regs16 = ['al', 'bl', 'cl', 'dl', 'di', 'si']
retreg16 = 'bp'

retvar = '@retvar'

def getallregs():
    return regs + [retreg, 'rsp']

def setmode(b):
    global regs
    global retreg
    global rsize
    global allregs
    if b == 64:
        regs = regs64
        retreg = retreg64
        rsize = 8
    elif b == 32:
        regs = regs32
        retreg = retreg32
        rsize = 4
    elif b == 16:
        regs = regs16
        retreg = retreg16
        rsize = 2
    allregs = getallregs()

completereglist = []
setmode(16)
completereglist += allregs
setmode(32)
completereglist += allregs
setmode(64)
completereglist += allregs
completereglist = list(set(completereglist))

setmode(64)

opmap = {
    '=' : 'mov',
    '+' : 'add',
    '-' : 'sub',
    '*' : 'imul',
    '|' : 'or',
    '&' : 'and',
    '^' : 'xor',
    '<<' : 'shl',
    '>>' : 'shr',
    '=' : 'mov',
    '::' : 'mov',
    '**' : 'powmacro'
}

compopmap = {
    '<' : 'jl',
    '>' : 'jg',
    '<=' : 'jle',
    '>=' : 'jge',
    '==' : 'je',
    '!=' : 'jne',
}

compopinvmap = {
    '<' : '>=',
    '>' : '<=',
    '<=' : '>',
    '>=' : '<',
    '==' : '!=',
    '!=' : '==',
}

def varbyreg(r):
    for v in localvars.keys():
        if localvars[v] == r : return v
    return None
    
def regbyvar(v):
    if v in localvars.keys() : return localvars[v]
    elif v[1:] in allregs : return v[1:]
    else : err("no variable '{}' in registers".format(v))

def doop():
    op = getok()
    if toptok() == '[':
        getok()
        var = getvar()
        match(']')
        src = expr()
        out('mov {}, {}'.format(varloc(var), varloc(src)))
    else : var = getreg()
    if toptok() == '[':
        getok()
        while toptok() != ']':
            if op in ['<<', '>>'] : val = getint()
            else : val = expr()
            out('{} {}, {}'.format(opmap[op], varloc(var), varloc(val)))
        getok()
    else:
        if op in ['<<', '>>'] : val = getint()
        else : val = expr()
        out('{} {}, {}'.format(opmap[op], varloc(var), varloc(val)))
    return var

def dodivop():
    op = getok()
    if toptok() == '[': 
        getok() 
        var = getvar() 
        match(']') 
        src = expr() 
        out('mov {}, {}'.format(varloc(var), varloc(src)))
    else : var = getvar()
    val = expr()
    va = varbyreg('rax')
    if va : push(va)
    vc = varbyreg('rcx')
    if vc : push(vc)
    vd = varbyreg('rdx')
    if vd : push(vd)
    out('mov rax, {}'.format(varloc(var)))
    out('mov rcx, {}'.format(varloc(val)))
    out('xor rdx, rdx')
    if op == '%32' : out('idiv ecx')
    else : out('idiv rcx')
    om = {'/' : 'rax', '%' : 'rdx', '%32' : 'rdx'}
    out('mov {}, {}'.format(regbyvar(var), om[op]))
    l = [va, vc, vd]
    i = 0
    for v in l:
        if v:
            i += 1
            r = localvars[v]
            if r != regbyvar(var):
                out('mov {}, {}'.format(r, varloc(v)))
    for a in range(i) : stk.pop()
    out('add rsp, {}'.format(i * 8))
    return var
    
def dowhile():
    class foreach:
        def __init__(self, val, src, size, off):
            self.val = val
            self.src = src
            self.size = size
            self.off = off
    loop = newname('loop')
    exit = newname('exit')
    getok()
    if toptok() == '[':
        getok()
        var = getvar()
        max = None
        min = None
        inc = '1'
        max = expr()
        if toptok() != ']':
            min = max
            max = expr()
            if toptok() != ']':
                inc = expr()
        match(']')
        foreaches = []
        while toptok() == '[':
            getok()
            val = getvar()
            src = expr()
            size = rsize
            off = '0'
            if toptok() != ']' : size = getint()
            if toptok() != ']' : off = expr()
            foreaches.append(foreach(val, src, size, off))
            match(']')
        if min != None : out('mov {}, {}'.format(varloc(var), varloc(min)))
        out('cmp {}, {}'.format(varloc(var), varloc(max)))
        out('jge {}'.format(exit))
        outlabel(loop)
        for fe in foreaches:
            val = fe.val
            src = fe.src
            times = int(fe.size)
            off = fe.off
            if not times in tmap.keys() : err("bad memory size '{}'".format(times))
            out('mov {}, [{} + {} * {} + {}]'.format(varloc(val), varloc(src), varloc(var), times, varloc(off)))
            if times < 8 : out('and {}, {}'.format(retreg, '0x' + 'ff' * times))
        body = expr()
        out('add {}, {}'.format(varloc(var), varloc(inc)))
        out('cmp {}, {}'.format(varloc(var), varloc(max)))
        out('jl {}'.format(loop))
        outlabel(exit)
    elif toptok() == '...':
        getok()
        outlabel(loop)
        body = expr()
        out('jmp {}'.format(loop))
    else: 
        outlabel(loop)
        if toptok() in compopmap.keys():
            op = getok()
            #if not op in compopmap.keys() : expect('comparison operator', op)
            var = getreg()
            val = getok()
        elif toptok() == '0':
            getok()
            op = '=='
            var = getreg()
            val = '0'
        else:
            op = '!='
            var = getreg()
            val = '0'
        invop = compopinvmap[op]
        cmp = 'cmp {}, {}'.format(varloc(var), varloc(val))
        jmp = '{} {}'.format(compopmap[invop], exit)
        out(cmp)
        out(jmp)
        #outlabel(loop)
        body = expr()
        #out(cmp)
        #out('{} {}'.format(compopmap[op], loop))
        out('jmp {}'.format(loop))
        outlabel(exit)
    return body

def doif():
    exit = newname('exit')
    elsel = newname('else')
    getok()
    iselse = False
    if toptok() == '?' : return dowhile()
    elif toptok() == ':':
        iselse = True
        getok()
    if toptok() in compopmap.keys():
        op = getok()
        #if not op in compopmap.keys() : expect('comparison operator', op)
        var = getreg()
        val = expr()
    elif toptok() == '0':
        getok()
        op = '=='
        var = getreg()
        val = '0'
    else:
        op = '!='
        var = getreg()
        val = '0'
    invop = compopinvmap[op]
    cmp = 'cmp {}, {}'.format(varloc(var), varloc(val))
    jmp = '{} {}'.format(compopmap[invop], elsel)
    out(cmp)
    out(jmp)
    body = expr()
    if iselse:
        out('jmp {}'.format(exit))
    outlabel(elsel)
    if iselse:
        expr()
        outlabel(exit)
    return body

def doprinti():
    getok()
    e = expr()
    out('printintmacro {}'.format(varloc(e)))
    return e

def docall():
    fname = getok()
    func = funcs[fname]
    arge = []
    for i in range(len(func.args)):
        arge.append(expr())
    return docallwithargs('{}{}'.format(funcpref, fname), arge)

def docallwithargs(fname, arge):
    vars = list(localvars.keys())
    #if len(arge) > 1 and arge.count(retvar) > 0:
    if arge.count(retvar) > 1:
        err("expression in function call arguments not saved to register")
    for v in vars:
        push(v)
    for i in range(len(arge)):
        a = arge[i]        
        r = regs[i]
        out('mov {}, {}'.format(r, varloc(a)))
    out('call {}'.format(fname))
    for v in vars:
        out('mov {}, {}'.format(localvars[v], varloc(v)))
    for v in vars:
        stk.pop()
    if len(vars) > 0 : out('add rsp, {}'.format(len(vars) * 8))
    return retvar

tmap = {
    1 : 'byte',
    2 : 'word',
    4 : 'dword',
    8 : 'qword',
}

def domalloc():
    if toptok() == '[':
        getok()
        
        size = int(getint())
        if not size in tmap:
            err('bad size for mem allocation')
        args = []
        while toptok() != ']':
            if toptok()[0] == '"':
                args.append(getok())
            else:
                args.append(expr())
        getok()
        length = 0
        for a in args:
            if a[0] == '"' : length += (len(a) - 2) * size
            else : length += size
        out('allocmacro {}'.format(length))
        i = 0
        for a in args:
            if a[0] == '"':
                for c in a[1:-1]:
                    out('mov {} [{} + {}], {}'.format(tmap[size], retreg, i, ord(c)))
                    i += size
            else:
                out('mov {} [{} + {}], {}'.format(tmap[size], retreg, i, varloc(a)))
                i += size
    else:
        e = expr()        
        out('allocmacro {}'.format(varloc(e)))
    return retvar

def dostring():
    a = getok()
    if a[0] != '"' or a[-1] != '"':
        err("not a valid string token")
    a = a[1:-1]
    size = len(a)
    out('allocmacro {}'.format(size + 1))
    i = 0
    for c in a:
        out('mov {} [{} + {}], {}'.format(tmap[1], retreg, i, ord(c)))
        i += 1
    out('mov {} [{} + {}], {}'.format(tmap[1], retreg, i, 0))
    return retvar

def dofold():
    f = getreg()
    start = expr()
    l = getreg()
    max = expr()
    if [f, start, l, max].count(retvar) > 1 : err('return register used more than once in args')
    for i in range(len(localvars)) : store(regs[i])
    usedregs = ['rax', 'rbx', 'rcx', 'rdx', 'rdi']
    out('mov rax, {}'.format(varloc(start)))
    out('mov rbx, {}'.format(varloc(l)))
    out('mov rcx, {}'.format(varloc(max)))
    out('mov rdx, {}'.format(varloc(f)))
    out('mov rdi, 0')
    loop = newname('loop')
    exit = newname('exit')
    out('cmp rdi, rcx')
    out('jge {}'.format(exit))
    outlabel(loop)
    for r in usedregs : out('push {}'.format(r))
    out('mov rbx, [rbx + rdi * 8]')
    out('call rdx')
    for r in usedregs[::-1] : out('pop {}'.format(r))
    out('mov rax, {}'.format(retreg))
    out('add rdi, 1')
    out('cmp rdi, rcx')
    out('jl {}'.format(loop))
    outlabel(exit)
    out('mov {}, rax'.format(retreg))
    
    for i in range(len(localvars)) : out('pop {}'.format(regs[len(localvars) - i - 1]))
    for i in range(len(localvars)) : stk.pop()

def dorange():
    min = '0'
    if toptok() == '[':
        getok()
        min = expr()
        max = expr()
        match(']')
    else : max = expr()
    push(varbyreg('rax'))
    push(varbyreg('rbx'))
    out('mov rax, {}'.format(varloc(max)))
    out('sub rax, {}'.format(varloc(min)))
    out('add rax, 2')
    out('imul rax, 8')
    out('allocmacro rax')
    out('mov rax, 0')
    out('mov rbx, {}'.format(varloc(min)))
    loop = newname('loop')
    outlabel(loop)
    out('mov [{} + rax * 8], rbx'.format(retreg))
    out('add rbx, 1')
    out('add rax, 1')
    out('cmp rax, {}'.format(varloc(max)))
    out('jle {}'.format(loop))
    out('pop rbx')
    out('pop rax')
    for i in range(2) : stk.pop()
    return retvar

def dolib():
    s = getok()[1:]
    if s == 'm':
        domalloc()
    elif s == 'f':
        e = expr()
        out('freemacro {}'.format(varloc(e)))
    elif s == 'ret':
        doret()
    elif s == 'fold':
        dofold()
    elif s == 'zip':
        dozip()
    elif s == 'range':
        dorange()
    elif s == 's':
        dostring()
    elif s == 'map':
        domap()
    return retvar
    
def doassign():
    getok()
    v = getvar()
    times = rsize
    off = 0
    if toptok() == '[':
        getok()
        i = expr()
        if toptok() != ']' : times = expr()
        if toptok() != ']' : off = expr()
        match(']')
    else : i = expr()
    times = int(times)
    if not times in tmap.keys() : err("bad memory size '{}'".format(times))
    e = expr()
    try:
        push(varbyreg('rax'))
        push(varbyreg('rbx'))
        push(varbyreg('rcx'))
        out('mov rax, {}'.format(varloc(e)))
        out('mov rbx, {}'.format(varloc(v)))
        out('mov rcx, {}'.format(varloc(i)))
        if times == 8 : r = 'rax'
        elif times == 4 : r = 'eax'
        elif times == 1 : r = 'al'
        elif times == 2:
            out('shl rax, 16')
            r = 'ax'
        out('mov {} [rbx + rcx * {} + {}], {}'.format(tmap[times], times, off, r))
        out('pop rcx')
        out('pop rbx')
        out('pop rax')
        for i in range(3) : stk.pop()
    except : err('array assignment error')
    return e
    
def doindex():
    getok()
    a = getvar()
    times = rsize
    off = 0 
    if toptok() == '[': 
        getok() 
        i = expr() 
        if toptok() != ']' : times = expr()
        if toptok() != ']' : off = expr()
        match(']') 
    else : i = expr()
    times = int(times)
    if not times in tmap.keys() : err("bad memory size '{}'".format(times))
    #out('mov {}, 0'.format(retreg))
    out('mov {}, [{} + {} * {} + {}]'.format(retreg, varloc(a), varloc(i), times, off))
    if times < 8 : out('and {}, {}'.format(retreg, '0x' + 'ff' * times))
    return retvar

def doret():
    e = expr()
    if not e == retvar : out('mov {}, {}'.format(retreg, varloc(e)))
    if len(stk) > 0 : out('add rsp, {}'.format(len(stk) * 8))
    out('ret')
    return None

def doasm():
    if toptok() == '$$':
        getok()
        s = ''
        t = getok()
        while t != ';':
            s += t + ' '
            t = getok()
        out(s)
    else:
        t = getok()
        t = t[1:]
        while t[0] == ' ' : t = t[1:]
        if t[0] == '{' : t = t[1:-1]
        out(t)
    
def dofp():
    getok()
    t = getok()
    if not t in funcs : err("no such function '{}'".format(t))
    out('mov {}, {}{}'.format(retreg, funcpref, t))
    return retvar
    
def dodfp():
    getok()
    r = getreg()
    out('push {}'.format(varloc(r)))
    args = []
    match('[')
    while toptok() != ']':
        args.append(expr())
    getok()
    out('pop {}'.format(retreg))
    return docallwithargs(retreg, args)
    
def doanonfunc():
    global localvars
    global stk
    oldvars = localvars.copy()
    oldstk = stk[:]
    localvars = {}
    stk = []
    fname = newname('anonfunc')
    skip = newname('skip')
    out('jmp {}'.format(skip))
    outlabel(fname)
    getok()
    rs = regs[::-1]
    args = []
    tmvars = lambda : err("too many arguments/variables")
    while toptok() != '=':
        name = getid()
        if len(rs) == 0 : tmvars()
        reg = rs.pop()
        localvars[name] = reg
        args.append(name)
    getok()
    while toptok() != ':':
        name = getid()
        if len(rs) == 0 : tmvars()
        reg = rs.pop()
        localvars[name] = reg
        val = getint()
        out('mov {}, {}'.format(reg, val))
    getok()
    while toptok() != ')' : last = expr()
    getok()
    if last == None : err("must return value at end of function")
    if last != '@retvar' : out('mov {}, {}'.format(retreg, varloc(last)))
    if len(stk) > 0 : out('add rsp, {}'.format(len(stk) * 8))
    out('ret')
    outlabel(skip)
    out('mov {}, {}'.format(retreg, fname))
    localvars = oldvars
    stk = oldstk
    return retvar
    
def store(r):
    if r in localvars.values() : push(varbyreg(r))
    else:
        out('push {}'.format(r))
        stk.append(None) 

def domap():    
    #getok()
    #src = getvar()
    func = expr()
    src = getvar()
    length = expr()
    usedregs = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi']
    for i in range(len(localvars)) : store(regs[i])
    out('mov rax, {}'.format(varloc(src)))
    out('mov rbx, {}'.format(varloc(func)))
    out('mov rcx, {}'.format(0))
    out('mov rdx, {}'.format(varloc(length)))
    out('mov r15, rdx')
    out('imul r15, 8')
    out('allocmacro r15')
    out('mov rdi, r15')
    loop = newname('loop')
    outlabel(loop)
    out('mov rsi, qword [rax + rcx * 8]')
    for r in usedregs : out('push {}'.format(r))
    #docallwithargs('rbx', ['%rsi'])
    out('mov rax, rsi')
    out('call rbx')
    for r in usedregs[::-1] : out('pop {}'.format(r))
    out('mov qword [rdi + rcx * 8], {}'.format(retreg))
    out('add rcx, 1')
    out('cmp rcx, rdx')
    out('jl {}'.format(loop))
    out('mov {}, rdi'.format(retreg))
    for i in range(len(localvars)) : out('pop {}'.format(regs[len(localvars) - i - 1]))
    for i in range(len(localvars)) : stk.pop()
    return retvar

def dozip():    
    #getok()
    #src = getvar()
    func = expr()
    srca = getvar()
    srcb = getvar()
    length = expr()
    usedregs = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp']
    for i in range(len(localvars)) : store(regs[i])
    out('mov rax, {}'.format(varloc(srca)))
    out('mov rbp, {}'.format(varloc(srcb)))
    out('mov rsi, {}'.format(varloc(func)))
    out('mov rcx, {}'.format(0))
    out('mov rdx, {}'.format(varloc(length)))
    out('mov r15, rdx')
    out('imul r15, 8')
    out('allocmacro r15')
    out('mov rdi, r15')
    loop = newname('loop')
    outlabel(loop)
    for r in usedregs : out('push {}'.format(r))
    #docallwithargs('rbx', ['%rsi'])
    out('mov rax, qword [rax + rcx * 8]')
    out('mov rbx, qword [rbp + rcx * 8]')
    out('call rsi')
    for r in usedregs[::-1] : out('pop {}'.format(r))
    out('mov qword [rdi + rcx * 8], {}'.format(retreg))
    out('add rcx, 1')
    out('cmp rcx, rdx')
    out('jl {}'.format(loop))
    out('mov {}, rdi'.format(retreg))
    for i in range(len(localvars)) : out('pop {}'.format(regs[len(localvars) - i - 1]))
    for i in range(len(localvars)) : stk.pop()
    return retvar

def dopush():
    getok()
    push(expr())
    
def dopop():
    getok()
    out('pop {}'.format(retreg))
    try : stk.pop()
    except : pass #err("popping return address")
    return retvar

def doprintstr():
    getok()
    e = expr()
    out('printstrmacro {}'.format(varloc(e)))
    return e
    
def doprintstrln():
    getok()
    e = expr()
    out('printstrlnmacro {}'.format(varloc(e)))
    return e
    
def doprintiln(): 
    getok() 
    e = expr()
    out('printintlnmacro {}'.format(varloc(e)))
    return e

def doprintchar():  
    getok()  
    e = expr()  
    out('printcharmacro {}'.format(varloc(e)))
    return e
    
def donot():
    getok()
    if toptok() == '[':
        getok()
        e = getreg()
        match(']')
        val = expr()
        out('mov {}, {}'.format(varloc(e), varloc(val)))
    else : e = getreg()
    out('not {}'.format(varloc(e)))
    return e
    
def dosqrt():
    getok()
    if toptok() == '[':
        getok()
        e = getreg()
        match(']')
        val = expr()
        out('mov {}, {}'.format(varloc(e), varloc(val)))
    else : e = getreg()
    out('sqrtmacro {}'.format(varloc(e)))
    return e

def doglobalassign():
    getok()
    if toptok() in globalvars.keys():
        glo = getok()
        reg = expr()
        rega = varloc(reg)
        regb = regs[0]
        if regb == rega : regb = regs[1]
        out('push {}'.format(regb))
        out('mov {}, {}'.format(regb, globalvars[glo]))
        out('mov qword [{}], {}'.format(regb, rega))
        out('pop {}'.format(regb))
        return reg
    else:
        reg = getreg()
        glo = getok()
        if glo in globalvars.keys():
            vreg = varloc(reg)
            out('mov {}, {}'.format(vreg, globalvars[glo]))
            out('mov {}, qword [{}]'.format(vreg, vreg))
            return reg
        elif glo in globalarrays.keys():
            out('mov {}, {}'.format(varloc(reg), globalarrays[glo]))
            return reg
        else:
            err("no such global '{}'".format(glo))
    
def doglobals():
    global dataoutput
    global globalvars
    global globalarrays
    
    def dataout(s):
        global dataoutput
        dataoutput += s + '\n'
    
    while toptok() != '\n':
        name = getid()
        if name in globalvars.keys() or name in globalarrays.keys():
            print(globalvars, globalarrays)
            err("duplicate global '{}'".format(name))
        nname = newname(name)
        if toptok() == '[':
            globalarrays[name] = nname
            getok()
            tmap = {
                1 : 'db',
                2 : 'dw',
                4 : 'dd',
                8 : 'dq',
            }
            size = int(getint())
            if not size in tmap:
                err('bad size for mem allocation')
            args = []
            while toptok() != ']':
                if toptok()[0] == '"':
                    args.append(getok())
                else:
                    args.append(expr())
            getok()
            s = "{} {} ".format(nname, tmap[size])
            if len(args) == 0 : err("nothing allocated")
            for a in args:
                if a[0] == '"':
                    for c in a[1:-1]:
                        s += '{}, '.format(ord(c))
                else:
                    s += '{}, '.format(a)
            s = s[:-2]
            dataout(s)
        else:
            globalvars[name] = nname
            val = getint()
            dataout('{} dq {}'.format(nname, val))

def doregnum():
    getok()
    n = getint()
    try : return '%' + allregs[int(n)]
    except : err("no register in range {}".format(n))

def skipcurlyblock():
    while toptok() != '}' : getok()
    getok()
    return None

def expr():
    if toptok() in opmap.keys() : return doop()
    elif toptok() in ['/', '%', '%32'] : return dodivop()
    elif toptok() == '%>' : return doregnum()
    elif len(toptok()) > 1 and toptok()[0] == '%' : return getok()
    elif toptok()[0] == "'" : return getok()
    elif toptok() == '?' : return doif()
    elif toptok()[0] == '@' : return dolib()
    elif toptok() == '!:' : return doassign()
    elif toptok() == '!!' : return doindex()
    elif toptok() == ';;' : return doglobalassign()
    elif toptok()[0] == '$' : return doasm()
    elif toptok() == '\\' : return dofp()
    elif toptok() == '\\>' : return dodfp()
    #elif toptok() == '>>=' : return domonad()
    elif toptok() == '>|' : return dopush()
    elif toptok() == '<|' : return dopop()
    elif toptok() == '!' : return donot()
    elif toptok() == '^/' : return dosqrt()
    elif toptok() == '_i' : return doprinti()
    elif toptok() == '_il' : return doprintiln()
    elif toptok() == '_s' : return doprintstr()
    elif toptok() == '_sl' : return doprintstrln()
    elif toptok() == '_c' : return doprintchar()
    elif toptok() == '@noret' : return getok()
    elif toptok() == '{' : return skipcurlyblock()
    elif toptok() in funcs.keys() : return docall()
    elif isalnum(toptok()) or isint(toptok()) : return getok()
    elif toptok() == '(':
        getok()
        if toptok() == '\\' : return doanonfunc()
        while toptok() != ')' : last = expr()
        getok()
        return last
    else : err("malformed expression '{}'".format(toptok()))

def startfunc():
    global localvars
    global stk
    stk = []
    funcname = getid()
    outlabel('{}{}'.format(funcpref, funcname))
    localvars = {}
    rs = regs[::-1]
    args = []
    tmvars = lambda : err("too many arguments/variables")
    while toptok() != '=':
        name = getid()
        if len(rs) == 0 : tmvars()
        reg = rs.pop()
        localvars[name] = reg
        args.append(name)
    getok()
    while toptok() != ':':
        name = getid()
        if len(rs) == 0 : tmvars()
        reg = rs.pop()
        localvars[name] = reg
        if toptok() == '_' : getok()
        else:
            val = getint()
            out('mov {}, {}'.format(reg, val))
    getok()
    last = None
    while toptok() != '\n' : last = expr()
    if last == None : err("must return value at end of function")
    elif last == '@noret' : pass 
    elif last != '@retvar' : out('mov {}, {}'.format(retreg, varloc(last)))
    if len(stk) > 0 : out('add rsp, {}'.format(len(stk) * 8))
    out('ret')
            
def dobitmode():
    n = int(getint())
    if not n in [16, 32, 64] : err('bad bitmode')
    setmode(n)
            
def domode():
    s = getok()[1:]
    if s == 'bitmode' : dobitmode()
    if s == 'g' : doglobals()
            
def startline():
    if toptok()[0] == '$' : doasm()
    elif toptok()[0] == '@' : domode()
    else : startfunc()
    
def findfuncs():
    global tokens
    global ln
    oldtokens = tokens[:]
    while toptok() == '\n' : getok()
    while len(tokens) > 1:
        if toptok()[0] == '$':
            getok()
            #getok()
        elif toptok()[0] == '@':
            t = getok()
            while t != '\n' : t = getok()
        else:
            fname = getid()
            args = []
            locals = []
            while toptok() != '=':
                name = getid()
                args.append(name)
            getok()
            while toptok() != ':':
                name = getid()
                #val = getint()
                getok()
                locals.append(name)
            getok()
            #if isint(toptok()) : args.pop()
            funcs[fname] = function(fname, args)
        while toptok() != '\n' : getok()
        while toptok() == '\n' and len(tokens) > 1 : getok()
    tokens = oldtokens
    ln = 1
    

def cexpr():
    opmap = {
        '+' : lambda a, b : a + b,
        '-' : lambda a, b : a - b,
        '*' : lambda a, b : a * b,
        '/' : lambda a, b : a / b,
        '**' : lambda a, b : int(a ** b),
        '<<' : lambda a, b : int(a * 2 ** b),
        '>>' : lambda a, b : int(a / 2 ** b)
    }
    mopmap = {
        '^/' : lambda a : int(a ** (0.5))
    }
    t = toptok()
    if t == '@c':
        getok()
        return cexpr()
    elif t in opmap.keys():
        getok()
        a = cexpr()
        b = cexpr()
        return opmap[t](a, b)
    elif t in mopmap.keys():
        getok()
        a = cexpr()
        return mopmap[t](a)
    else : return int(getint())

def doconstexpr(toks):
    global tokens
    tokens = toks
    getok = getokraw
        
    ntoks = []
    while len(tokens) > 1:
        t = getok()
        if t == '@c' : ntoks.append(str(cexpr()))
        else : ntoks.append(t)
    ntoks.append('\n')
    return ntoks[::-1]

class macro:
    def __init__(self, args, tokens):
        self.args = args
        self.tokens = tokens

def findmacros(toks):
    global tokens
    global ln
    getok = getokraw
    macros = {}
    tokens = toks
    ntoks = []
    while toptok() == '\n' : getok()
    while len(tokens) > 1:
        if toptok()[0] == '$':
            ntoks.append(getok())
            #ntoks.append(getok())
        elif toptok()[0] == '@':
            t = getok()
            ntoks.append(t)
            while t != '\n':
                t = getok()
                ntoks.append(t)
        else:
            fname = getok()
            args = []
            locals = []
            while toptok() != '=' and toptok() != '~':
                #name = getid()
                name = getok()
                args.append(name)
            if toptok() == '~':
                getok()
                mtokens = []
                while toptok() != '\n':
                    mt = getok()
                    if mt[0] != '\n' : mtokens.append(mt)
                    else : ntoks.append(mt)
                #mtokens = [t for t in mtokens if t[0] != '\n' or len(t) == 1]
                #print(mtokens)
                #print(len([n for n in mtokens if n[0] == '\n']))
                macros[fname] = macro(args, mtokens)
            else:
                ntoks.append(fname)
                for a in args : ntoks.append(a)
                while toptok() != '\n' : ntoks.append(getok())
        while toptok() == '\n' and len(tokens) > 1 : ntoks.append(getok()) 
    #print(ntoks)
    #print(len([n for n in ntoks if n[0] == '\n']))
    return ntoks, macros

def common_member(a, b): 
    a_set = set(a) 
    b_set = set(b) 
    if (a_set & b_set): 
        return True 
    else: 
        return False

def dorepeatmacros(toks):
    global tokens
    getok = getokraw
    tokens = toks
    ntoks = []
    while len(tokens) > 1:
        t = getok()
        if t == '*~':
            m = getok()
            if m == '(':
                depth = 0
                t = getok()
                expand = []
                while depth > 0 or t != ')':
                    expand.append(t)
                    if t == '(' : depth += 1
                    elif t == ')' : depth -= 1
                    t = getok()
            else : expand = [m]
            length = cexpr()
            for i in range(int(length)):
                for e in expand:
                    if e == 'i~' : ntoks.append(str(i))
                    else : ntoks.append(e)
        else : ntoks.append(t)
    ntoks.append('\n')
    return ntoks[::-1]

def execrepeatmacros(toks):
    global tokens
    tokens = toks
    oldtokens = tokens[:]
    for i in range(30):
        ntoks = dorepeatmacros(tokens)
        tokens = ntoks
        if tokens == oldtokens : break
        oldtokens = tokens[:]
    return tokens
    
def doaddmacros(toks):
    toks = toks[::-1]
    ntoks = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == '+~':
            i += 1
            ntoks.append(ntoks.pop() + toks[i])
        else : ntoks.append(t)
        i += 1
    return ntoks[::-1]

def domacros(prog):
    global tokens
    tokens = ['\n'] + tokenize(prog)
    #tokens, macros = findmacros(tokens)
    #tokens = domacroreplace(tokens, macros)
    
    #print(tokens)
    tokens, macros = findmacros(tokens)
    for i in range(30):
        tokens = domacroreplace(tokens, macros)
        if not common_member(tokens, macros.keys()) : break        
    #print(tokens)
    if common_member(tokens, macros.keys()):
        culprit = None
        for m in macros.keys():
            if m in tokens:
                culprit = m
                break
        global ln
        ln = 0
        err("macro '{}' recursion overflow".format(culprit))
    #print(tokens)
    tokens = ['\n'] + tokens[::-1]
    tokens = execrepeatmacros(tokens)
    tokens = doconstexpr(tokens)
    tokens = doaddmacros(tokens)
    return tokens
    
def domacroreplace(toks, macros):
    global tokens
    getok = getokraw
    tokens = toks[::-1]
    ntoks = []
    while len(tokens) > 1:
        t = getok()
        if t in macros.keys():
            m = macros[t]
            argmap = {}
            for a in m.args:
                v = getok()
                if v == '(':
                    depth = 0
                    l = []
                    t = getok()
                    while depth > 0 or t != ')':
                        if t == '(' : depth += 1
                        elif t == ')' : depth -= 1
                        l.append(t)
                        t = getok()
                    argmap[a] = l
                else : argmap[a] = [v]
            for tok in m.tokens:
                if tok in argmap.keys():
                    ntoks += argmap[tok]
                else : ntoks.append(tok)
        else : ntoks.append(t)
    return ntoks + ['\n']

class compileresult:
    def __init__(self):
        self.output = None
        self.dataoutput = None
        self.funcs = None

def start(prog, noasm=False):
    global tokens
    global localvars
    global output
    global stk
    global ln
    global globalvars
    global globalarrays
    output = ''
    localvars = {}
    stk = []
    globalvars = {}
    globalarrays = {}
    baseln = 0
    #tokens = tokenize(prog)
    baseln = 0
    for i in range(len(prog)):
        c = prog[i]
        if c == '\n' : baseln += 1
        elif not c.isspace() : break
    baseln += 1
    tokens = domacros(prog)
    #print(len([n for n in tokens if n[0] == '\n']))
    #tokens = tokenize(prog)
    #print(' '.join(tokens[::-1]))
    ln = baseln
    findfuncs()
    ln = baseln
    #print(len([n for n in tokens if n[0] == '\n']))
    #print(ln)
    result = compileresult()
    if not noasm:
        while len(tokens) > 1 and toptok() == '\n' : getok()
        while len(tokens) > 1:
            startline()
            match('\n')
            while len(tokens) > 1 and toptok() == '\n' : getok()
        result.dataoutput = dataoutput
        result.output = output
    result.funcs = funcs
    return result
    
def genids(max):
    
    from string import ascii_lowercase
    import itertools

    def iter_all_strings():
        for size in itertools.count(1):
            for s in itertools.product(ascii_lowercase, repeat=size):
                yield "".join(s)
    
    result = []
    i = 0
    for s in iter_all_strings():
        result.append(s)
        i += 1
        if i >= max : break
    return result
        
    
def compress(prog):
    tokens = tokenize(prog)[::-1]
    
    ids = []
    expt = ['main', '_i']
    for t in tokens:
        if isalnum(t) and not t in expt and not t in ids:
            ids.append(t)
    rids = genids((len(ids) + len(expt)) * 2)
    for t in expt + ids:
        if t in rids : rids.remove(t)
    rep = {ids[i] : rids[i] for i in range(len(ids)) if len(rids[i]) < len(ids[i])}
        
    lasttok = ''
    result = ''
    for t in tokens:
        if t in rep.keys() : t = rep[t]
        if isalnum(t) and isalnum(lasttok) or isint(t) and isint(lasttok):
            result += ' '
        if not (len(t) > 1 and t[0] == '\n'):
            result += t
        lasttok = t
    return result
    
def main():
    if len(sys.argv) != 2:
        print('wrong number of parameters')
        sys.exit(0)
    prog = open(sys.argv[1]).read()
       
    cresult = start(prog)
    dataoutput = cresult.dataoutput
    output = cresult.output

    #comp = compress(prog)

    mtokens = domacros(prog)
    mprog = ' '.join(mtokens[::-1]).strip()

    print('Source:')
    print(prog + '\n')
    #print('Compressed:')
    #print(comp + '\n')
    print('Macro Expansion:')
    print(mprog)
    print('Assembly:')
    print(output)
    pl = len(prog)
    ol = len(output)
    print("""
    program length: {} chars, {} lines
    assembly length: {} chars, {} lines
    ratio: {}%
    """.format(pl, len(prog.split('\n')), ol, len(output.split('\n')), int(float(pl) / float(ol) * 100)))

if __name__ == "__main__":
    main()