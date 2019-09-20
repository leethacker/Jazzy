import re
import subprocess
import sys

debugerr = False

output = ''
dataoutput = '\n'
dolnout = False
ln = 1
funcpref = 'func_'
stk = []
globalvars = {}
globalarrays = {}
globalbuffers = {}
patternmatches = {}

funcs = {}
class function:
    def __init__(self, name, args, ispublic, isimported=False):
        self.name = name
        self.args = args
        self.ispublic = ispublic
        self.isimported = isimported

def tokenize(s):
    s = re.sub(r'#.*\n', '\n', s + '\n')
    mcs = r';;|\*\*|\^/|%32|\*~|>\||<\||\|>|>>=|\\<|\.\.\.|\\>|::|<<|>>|!\*|!!|!:|==|!=|<=|>='
    r = mcs + r'|gi~|\+~|i~|%>|\$\$|`[a-zA-Z0-9_]+|\'[^\']\'|"[^"]*"|\$ *\{[^\}]*}|\$[^\n]*|[@`]?[_a-zA-Z]+|\-?[0-9]+|%[_a-zA-Z0-9]+|\n[^\S\n]*|\S'
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

def toint(s):
    try : return int(s)
    except : return ord(s)

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

def varloc(s, nostk=False):
    if s == None : err('not a valid value')
    if s[0] == "'" : return ord(s[1:-1])
    elif len(s) > 1 and s[0] == '%':
        r = s[1:]
        if not r in completereglist : err("no such register ''".format(r))
        return r
    elif s in stk and not nostk: return 'qword [rsp + {}]'.format(stk[::-1].index(s) * 8)
    elif s in localvars.keys() : return localvars[s]
    elif isint(s) : return s
    elif s == '@retvar' : return retreg
    else:
        err("could not find var '{}'".format(s))
    
def push(s):
    out('push {}'.format(varloc(s)))
    stk.append(s)

asmretreg = 'r15'
def adjustretreg():
    if retreg != asmretreg : out('mov {}, {}'.format(retreg, asmretreg))

regs64 = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14']
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

def setcallconv(conv):
    global regs64
    global retreg64
    if conv == 'Jazzy':
        regs64 = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14']
        retreg64 = 'r15'
    elif conv == 'C':
        regs64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'rbx', 'rbp', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        retreg64 = 'rax'
    else : err("unrecognized calling convention '{}'".format(conv))
    setmode(64)

completereglist = []
setmode(16)
completereglist += allregs
setmode(32)
completereglist += allregs
setmode(64)
completereglist += allregs
completereglist = list(set(completereglist))

setcallconv('C')#('Jazzy')
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
    if r == retreg : return retvar
    return None
    
def regbyvar(v):
    if v in localvars.keys() : return localvars[v]
    elif v[1:] in allregs : return v[1:]
    else : err("no variable '{}' in registers".format(v))

def doop():
    op = getok()
    if toptok() == '[':
        getok()
        var = getreg()#getvar()
        match(']')
        src = expr()
        if toptok() != '[' and (op in ['+', '*'] and (isint(src) or isint(toptok())) or op in ['-'] and isint(toptok())):
            val = expr()
            if isint(src) and isint(val) : out('mov {}, {} {} {}'.format(varloc(var), src, op, val))
            else : out('lea {}, [{} {} {}]'.format(varloc(var), varloc(src), op, varloc(val)))
            return var
        else : out('mov {}, {}'.format(varloc(var), varloc(src)))
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
        elif op in ['::', '='] and toptok() == '<|':
            getok()
            out('pop {}'.format(varloc(var)))
            stk.pop()
            return var
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
            r = retreg if v == retvar else localvars[v]
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
        cmpop = '<'
        if toptok() in compopmap.keys() : cmpop = getok()
        var = getvar()
        max = None
        min = None
        isinfinite = False
        inc = '1' #if not cmpop in ['>', '>='] else '-1'
        if toptok() == '...':
            isinfinite = True
            max = '0'
            getok()
        else:
            max = expr()
            if toptok() != ']':
                min = max
                if toptok() == '...':
                    isinfinite = True
                    max = '0'
                    getok()
                else : max = expr()
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
        if not isinfinite:
            out('cmp {}, {}'.format(varloc(var), varloc(max)))
            out('{} {}'.format(compopmap[compopinvmap[cmpop]], exit))
        outlabel(loop)
        for fe in foreaches:
            val = fe.val
            src = fe.src
            times = int(fe.size)
            off = fe.off
            if not times in tmap.keys() : err("bad memory size '{}'".format(times))
            out('mov {}, [{} + {} * {} + {}]'.format(varloc(val), varloc(src), varloc(var), times, varloc(off)))
            if times < 8 : out('and {}, {}'.format(varloc(val), '0x' + 'ff' * times))
        body = expr()
        out('{} {}, {}'.format('add' if not cmpop in ['>', '>='] else 'sub', varloc(var), varloc(inc)))
        if isinfinite:
            out('jmp {}'.format(loop))
        else:
            out('cmp {}, {}'.format(varloc(var), varloc(max)))
            out('{} {}'.format(compopmap[cmpop], loop))
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
            val = expr() #getok()
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
        if val == '0' and op in ['==', '!=']:
            cmp = 'test {0}, {0}'.format(varloc(var))
        else:
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
    isternary = False
    if toptok() == '?' : return dowhile()
    elif toptok() == ':':
        iselse = True
        getok()
    elif toptok() == '.':
        iselse = True
        isternary = True
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
    if op in ['==', '!='] and val == '0':
        cmp = 'test {0}, {0}'.format(varloc(var))
        jmp = '{} {}'.format(compopmap[invop], elsel)
    else:
        cmp = 'cmp {}, {}'.format(varloc(var), varloc(val))
        jmp = '{} {}'.format(compopmap[invop], elsel)
    out(cmp)
    out(jmp)
    body = expr()
    if isternary : out('mov {}, {}'.format(retreg, varloc(body)))
    if iselse:
        out('jmp {}'.format(exit))
    outlabel(elsel)
    if iselse:
        ebody = expr()
        if isternary : out('mov {}, {}'.format(retreg, varloc(ebody)))
        outlabel(exit)
        if isternary : return retvar
    return body

def doprinti():
    getok()
    e = expr()
    out('printintmacro {}'.format(varloc(e)))
    return e

def docall(dotarg=None):
    fname = getok()
    fp = funcpref
    func = funcs[fname]
    arge = []
    if dotarg != None : arge.append(dotarg)
    if toptok() == '(':
        getok()
        cstyle = True
        if toptok() == '\\' : cstyle = False
        if not cstyle:
            tokens.append('(')
        for i in range(1 if dotarg else 0, len(func.args)):
            arge.append(expr())
            if cstyle:
                if i != len(func.args) - 1 : match(',')
        if cstyle : match(')')
    else:
        for i in range(1 if dotarg else 0, len(func.args)):
            arge.append(expr())
    if func.isimported : fp = ''
    return docallwithargs('{}{}'.format(fp, fname), arge)

def docallwithargs(fname, arge, usingretreg=False):
    vars = list(localvars.keys())
    #if len(arge) > 1 and arge.count(retvar) > 0:
    if arge.count(retvar) > (0 if usingretreg else 1):
        err("expression in function call arguments not saved to register")
    for v in vars:
        push(v)
    rs = regs[::-1]
    for i in range(len(arge)):
        a = arge[i]        
        r = regs[i]
        loc = varloc(a, nostk=True)
        if loc in rs: #throw in a "False and" if it misbehaves
            if loc != r : out('mov {}, {}'.format(r, loc))
        else : out('mov {}, {}'.format(r, varloc(a)))
        rs.pop()
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
    allocmacro = 'jzallocmacro' if jzalloc else 'allocmacro'
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
        out('{} {}'.format(allocmacro, length))
        
        adjustretreg()
        
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
        out('{} {}'.format(allocmacro, varloc(e)))
        adjustretreg()
    return retvar

def dostring():
    a = getok()
    if a[0] != '"' or a[-1] != '"':
        err("not a valid string token")
    a = a[1:-1]
    size = len(a)
    out('{} {}'.format('jzallocmacro' if jzalloc else 'allocmacro', size + 1))
    adjustretreg()
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
    saveregs = usedregs[1:]
    out('mov rdx, {}'.format(varloc(f)))
    out('mov rax, {}'.format(varloc(start)))
    out('mov rbx, {}'.format(varloc(l)))
    out('mov rcx, {}'.format(varloc(max)))
    out('mov rdi, 0')
    loop = newname('loop')
    exit = newname('exit')
    out('cmp rdi, rcx')
    out('jge {}'.format(exit))
    outlabel(loop)
    for r in saveregs : out('push {}'.format(r))
    out('mov {}, [rbx + rdi * 8]'.format(getallregs()[1]))
    out('mov {}, rax'.format(getallregs()[0]))
    out('call rdx')
    for r in saveregs[::-1] : out('pop {}'.format(r))
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
    if 'rax' in localvars.values() : push(varbyreg('rax'))
    if 'rbx' in localvars.values() : push(varbyreg('rbx'))
    out('mov rax, {}'.format(varloc(max)))
    out('sub rax, {}'.format(varloc(min)))
    out('add rax, 2')
    out('imul rax, 8')
    out('allocmacro rax')
    out('mov rax, 0')
    out('mov rbx, {}'.format(varloc(min)))
    loop = newname('loop')
    outlabel(loop)
    out('mov [r15 + rax * 8], rbx')
    out('add rbx, 1')
    out('add rax, 1')
    out('cmp rax, {}'.format(varloc(max)))
    out('jle {}'.format(loop))
    if 'rax' in localvars.values():
        out('pop rbx')
        stk.pop()
    if 'rbx' in localvars.values():
        out('pop rax')
        stk.pop()
    out('mov {}, r15'.format(retreg))
    return retvar

def dors() : return str(rsize)

def dolib():
    s = getok()[1:]
    if s == 'm':
        domalloc()
    elif s == 'f':
        e = expr()
        out('{}freemacro {}'.format('jz' if jzalloc else '', varloc(e)))
    elif s == 'ret' : doret()
    #elif s == 'fold' : dofold()
    #elif s == 'zip' : dozip()
    #elif s == 'range' : dorange()
    #elif s == 'rep' : dorep()
    elif s == 's' : dostring()
    #elif s == 'map' : domap()
    elif s == 'rs' : return dors()
    elif s == 'rr' : pass
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
        topush = ['rax', 'rbx', 'rcx']
        for r in topush:
            var = varbyreg(r)
            if var != None : push(var)
            else:
                out('push {}'.format(r))
                stk.append(None)
        
        out('mov rax, {}'.format(varloc(e)))
        out('mov rbx, {}'.format(varloc(v)))
        out('mov rcx, {}'.format(varloc(i)))

        if times == 8 : r = 'rax'
        elif times == 4 : r = 'eax'
        elif times == 1 : r = 'al'
        elif times == 2:
            #out('shl rax, 32')
            r = 'ax'
        out('mov {} [rbx + rcx * {} + {}], {}'.format(tmap[times], times, off, r))
        out('pop rcx')
        out('pop rbx')
        out('pop rax')
        for i in range(3) : stk.pop()
    except:
        err('array assignment error')
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
    instr = 'mov'
    if times < 8:
        out('mov {}, {}'.format(retreg, '0x' + 'ff' * times))
        instr = 'and'
    out('{} {}, [{} + {} * {} + {}]'.format(instr, retreg, varloc(a), varloc(i), times, off))
    return retvar

def doderef():
    getok()
    a = getreg()
    out('mov {}, qword [{}]'.format(retreg, varloc(a)))
    return retvar

def doret():
    e = expr()
    if not e == retvar : out('mov {}, {}'.format(retreg, varloc(e)))
    if len(stk) > 0 : out('add rsp, {}'.format(len(stk) * 8))
    out('ret')
    return None

def doasm():
    result = ''
    if toptok() == '$$':
        getok()
        s = ''
        t = getok()
        while t != ';':
            s += t + ' '
            t = getok()
    else:
        t = getok()
        t = t[1:]
        while t[0] == ' ' : t = t[1:]
        if t[0] == '{' : t = t[1:-1]
        s = t
    varmode = False
    var = ''
    firstvar = None
    for c in s:
        if varmode:
            if isalnum(c) : var += c
            else:
                if not firstvar : firstvar = var
                result += varloc(var)
                result += c
                varmode = False
                var = ''
        elif c == '\\' : varmode = True
        else : result += c
    out(result)
    return firstvar
    
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
    if toptok() == '(':
        getok()
        while toptok() != ')':
            args.append(expr())
            if toptok() != ')' : match(',')
        getok()
    else:
        match('[')
        while toptok() != ']':
            args.append(expr())
        getok()
    out('pop {}'.format(retreg))
    return docallwithargs(retreg, args, usingretreg=True)
    
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
        if toptok() == '_' : getok()
        else:
            val = getint()
            out('mov {}, {}'.format(reg, val))
    getok()
    while toptok() != ')' : last = expr()
    getok()
    if last == None : err("must return value at end of function")
    if varloc(last) != retreg : out('mov {}, {}'.format(retreg, varloc(last)))
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

#possibly unstable
def dopush():
    getok()
    #push(expr())
    e = expr()
    out('push {}'.format(varloc(e)))
    stk.append(None)
    
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

def dataout(s):
    global dataoutput
    dataoutput += s + '\n'
    
def doglobals():
    global dataoutput
    global globalvars
    global globalarrays
    
    while toptok() != '\n':
        name = getid()
        if name in globalvars.keys() or name in globalarrays.keys():
            #print(globalvars, globalarrays)
            err("duplicate global '{}'".format(name))
        nname = newname(name)
        if toptok() == '<':
                getok()
                bufsize = getint()
                globalarrays[name] = nname
                globalbuffers[name] = bufsize
                match('>')
        elif toptok() == '[':
                getok()
                globalarrays[name] = nname
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

def dorawstr():
    s = getok()
    name = newname('rawstr')
    escape = False
    vals = []
    escmap = {'n' : 10, 't' : 9, '0' : 0}
    for c in s[1:-1]:
        if escape:
            if c in escmap : vals.append(str(escmap[c]))
            else : vals.append(str(ord(c)))
            escape = False
        elif c == '\\' : escape = True
        else : vals.append(str(ord(c)))
    ds = ', '.join(vals)
    if s[1:-1] : dataout('{} db {}, 0'.format(name, ds))    
    else : dataout('{} db 0'.format(name))
    out('mov {}, {}'.format(retreg, name))
    return retvar

def doregnum():
    getok()
    n = getint()
    try : return '%' + allregs[int(n)]
    except : err("no register in range {}".format(n))

def dorrstore():
    getok()
    e = expr()
    ve = varloc(e)
    if ve != retvar:
        out('mov {}, {}'.format(retreg, ve))
    return retvar

def skipcurlyblock():
    while toptok() != '}' : getok()
    getok()
    return None
    
def dotcheck(val):
    if toptok() == '.':
        getok()
        if not toptok() in funcs.keys() : err("no func '{}'".format(toptok()))
        return dotcheck(docall(dotarg=val))
    else : return val#err("malformed expression '{}'".format(val)) #return val

def expr():
    if toptok() in opmap.keys() : return doop()
    elif toptok() in ['/', '%', '%32'] : return dodivop()
    elif toptok() == '%>' : return doregnum()
    elif len(toptok()) > 1 and toptok()[0] == '%' : return dotcheck(getok())
    elif toptok()[0] == "'" : return dotcheck(getok())
    elif len(toptok()) >= 2 and toptok()[0] == '"' and toptok()[-1] == '"' : return dotcheck(dorawstr())
    elif toptok() == '?' : return doif()
    elif toptok()[0] == '@' : return dotcheck(dolib())
    elif toptok() == '!:' : return doassign()
    elif toptok() == '!!' : return doindex()
    elif toptok() == '!*' : return doderef()
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
    elif toptok() == '|>' : return dorrstore()
    elif toptok() == '@noret' : return getok()
    elif toptok() == '{' : return skipcurlyblock()
    elif toptok() in localvars.keys() : return dotcheck(getok())
    elif toptok() in funcs.keys() : return dotcheck(docall())
    elif isint(toptok()) : return dotcheck(getok())
    elif toptok() == '(':
        last = None
        getok()
        if toptok() == '\\' : return doanonfunc()
        while toptok() != ')' : last = expr()
        getok()
        if last == None : err('nothing in parenthesis')
        return dotcheck(last)
    else : err("malformed expression '{}'".format(toptok()))

def startfunc():
    global localvars
    global stk
    stk = []
    if toptok() == '>':
        getok()
        out("global {}".format(toptok()))
        #out("global _{}".format(toptok()))
        out("global {}{}".format(funcpref, toptok()))
        if funcpref != "" : outlabel(toptok())
        #outlabel('_{}'.format(toptok()))
    funcname = getid()
    localvars = {}
    rs = regs[::-1]
    args = []
    tmvars = lambda : err("too many arguments/variables")
    ispattern = False
    patternargs = []
    while toptok() != '=':
        if toptok() == '[' : name = getok()
        elif isint(toptok()) : name = getint()
        else : name = getid()
        if len(rs) == 0 : tmvars()
        reg = rs.pop()
        if name == '[':
            ispattern = True
            pat = '['
            while toptok() != ']' : pat += (getint() if toptok() != '_' else getok()) + ' '
            getok()
            pat = list(pat)
            pat[-1] = ']'
            pat = ''.join(pat)
            patternargs.append(pat)
        elif isint(name):
            ispattern = True
            patternargs.append(name)
        else:
            localvars[name] = reg
            args.append(name)
            patternargs.append(None)
    genpatternlabel = lambda funcpref, funcname, patternargs : \
        "{}{}_@pattern_{}".format(funcpref, funcname, '_'.join([str(i) for i in patternargs]).replace('[', '@').replace(']', '@').replace(' ', '_'))
    if ispattern : outlabel(genpatternlabel(funcpref, funcname, patternargs))
    else : outlabel('{}{}'.format(funcpref, funcname))
    if False and funcname in ['main', '_main']:
        if len(args) >= 1 : out('mov rax, rdi')
        if len(args) >= 2 : out('mov rbx, rsi')
    if not ispattern and funcname in patternmatches:
        patterns = patternmatches[funcname]
        for p in patterns:
            rp = regs[::-1]
            skip = newname('skip')
            for n in p:
                r = rp.pop()
                if n != None:
                    if isint(n):
                        out('cmp {}, {}'.format(r, n))            
                        out('jne {}'.format(skip))
                    else:
                        n = n[1:-1].split(' ')[::-1]
                        memsize = toint(n.pop())
                        n = n[::-1]
                        for i in range(len(n)):
                            num = n[i]
                            if num != '_':
                                out('mov {}, [{} + {}]'.format(retreg, r, i * memsize))
                                if memsize < 8 : out('and {}, {}'.format(retreg, '0x' + 'ff' * memsize))
                                out('cmp {}, {}'.format(retreg, num))            
                                out('jne {}'.format(skip))
            out("jmp {}".format(genpatternlabel(funcpref, funcname, p)))
            outlabel(skip)
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
    elif last != '@retvar' and varloc(last) != retreg : out('mov {}, {}'.format(retreg, varloc(last)))
    if len(stk) > 0 : out('add rsp, {}'.format(len(stk) * 8))
    out('ret')
            
def dobitmode():
    n = int(getint())
    if not n in [16, 32, 64] : err('bad bitmode')
    setmode(n)
            
def dofpref():
    global funcpref
    s = getok()
    if len(s) < 2 or s[0] != '"' or s[-1] != '"' : expect("string literal", s)
    funcpref = s[1:-1]
            
def domode():
    s = getok()[1:]
    if s == 'bitmode' : dobitmode()
    elif s == 'g' : doglobals()
    elif s == 'fpref' : dofpref()
    elif s == 'callconv' : setcallconv(getok())

def ismode(s) : return s[1:] in ['bitmode', 'g', 'fpref', 'callconv']
            
def startline():
    if toptok()[0] == '$' : doasm()
    elif toptok()[0] == '@' : domode()
    elif toptok() == '<':
        while toptok() != '\n' : getok()
    elif toptok() == '{':
        while toptok() != '}' : getok()
        getok()
    else : startfunc()
    
def findfuncs(infindpublics=False):
    global tokens
    global ln
    oldtokens = tokens[:]
    importedbasics = True
    while toptok() == '\n' : getok()
    while len(tokens) > 1:
        if toptok()[0] == '$':
            getok()
            #getok()
        elif toptok()[0] == '@':
            if toptok() == '@fpref': 
                t = getok()
                dofpref()
            else : t = getok()
            while toptok() != '\n' : t = getok()
        elif not importedbasics or toptok() == '<' and not infindpublics:
            nofunc = False
            if importedbasics:
                getok()
                fname = getid()
            if isint(toptok()):
                argnum = int(getint())
                args = ['arg{}'.format(i) for i in range(argnum)]
            elif not importedbasics or toptok() == '.':
                if importedbasics:
                    getok()
                    match('jz')
                    filename = fname + '.jz'
                    try : txt = open(filename).read()
                    except:
                        try : txt = open('./standardlib/'+filename).read()
                        except : err("couldn't import file '{}'".format(filename))
                    importfuncs = getpublics(txt)
                else : importfuncs = getpublics(open('./standardlib/basic.jz').read())
                for fname in importfuncs.keys():
                    f = importfuncs[fname]
                    f.isimported = True
                    f.ispublic = False
                    out('extern {}'.format(fname))
                    #out('extern {}{}'.format(funcpref, fname))
                    funcs[fname] = f
                #print(importfuncs)
                nofunc = True
                importedbasics = True
            else:
                args = []
                while toptok() != '\n':
                    args.append(getid())
            if not nofunc:
                funcs[fname] = function(fname, args, True, isimported=True)
                out('extern {}'.format(fname))
                out('extern {}{}'.format(funcpref, fname))
        elif toptok() == '<':
            while toptok() != '\n' : getok()
        elif toptok() == '{':
            t = getok()
            while toptok() != '}' : t = getok()
        else:
            isargmatch = False
            argpattern = []
            if toptok() == '>':
                ispublic = True
                getok()
            else : ispublic = False
            fname = getid()
            args = []
            locals = []
            while toptok() != '=':
                if toptok() == '[' : name = getok()
                elif not isint(toptok()) : name = getid()
                else : name = getint()
                if isint(name):
                    isargmatch = True
                    argpattern.append(name)
                elif name == '[':
                    isargmatch = True
                    pat = '['
                    while toptok() != ']' : pat += (getint() if toptok() != '_' else getok()) + ' '
                    getok()
                    pat = list(pat)
                    pat[-1] = ']' 
                    pat = ''.join(pat)                   
                    argpattern.append(pat)
                else : argpattern.append(None)
                args.append(name)
            getok()
            while toptok() != ':':
                name = getid()
                getok()
                locals.append(name)
            getok()
            if isargmatch:
                if not fname in patternmatches : patternmatches[fname] = []
                patternmatches[fname].append(argpattern)
            else : funcs[fname] = function(fname, args, ispublic)
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

globalmacros = {}

def getglobalmacros():
    global tokens
    oldtokens = tokens
    tokens = tokenize(open('./standardlib/macros.jzm').read() + '\n')
    t, macros = findmacros(tokens)
    for m in macros:
        globalmacros[m] = macros[m]
    tokens = oldtokens

def findmacros(toks):
    global tokens
    global ln
    getok = getokraw
    macros = globalmacros.copy()
    tokens = toks
    ntoks = []
    while toptok() == '\n' : getok()
    while len(tokens) > 1:
        if toptok()[0] == '$':
            ntoks.append(getok())
            #ntoks.append(getok())
        elif toptok()[0] == '@' and ismode(toptok()) or toptok() in ['<', '>']:
            t = getok()
            ntoks.append(t)
            while t != '\n':
                t = getok()
                ntoks.append(t)
        elif toptok() == '{':
            ntoks.append('{')
            while toptok() != '}':
                t = getok()
                ntoks.append(t)
            ntoks.append(getok())
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
    
#also does gi~ macros
def doaddmacros(toks):
    toks = toks[::-1]
    ntoks = []
    i = 0
    gi = 0
    while i < len(toks):
        t = toks[i]
        if t == '+~':
            i += 1
            ntoks.append(ntoks.pop() + toks[i])
        elif t == 'gi~':
            ntoks.append(str(gi))
            gi += 1
        else : ntoks.append(t)
        i += 1
    return ntoks[::-1]

def domacros(prog):
    global tokens
    tokens = ['\n'] + tokenize(prog)
    #tokens, macros = findmacros(tokens)
    #tokens = domacroreplace(tokens, macros)
    
    #print(tokens)
    getglobalmacros()
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

def getpublics(prog):
    global tokens
    global localvars
    global output
    global stk
    global ln
    global globalvars
    global globalarrays
    global funcs
    global funcpref
    
    oldoutput = output
    oldlocalvars = localvars
    oldstk = stk
    oldglobalvars = globalvars
    oldglobalarrays = globalarrays
    oldfuncs = funcs
    oldfuncpref = funcpref
    oldtokens = tokens
    
    output = ''
    localvars = {}
    stk = []
    globalvars = {}
    globalarrays = {}
    baseln = 0
    funcs = {}
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
    findfuncs(infindpublics=True)
    result = {f.name : f for f in funcs.values() if f.ispublic}
    for f in list(result.keys())[:]:
        result[funcpref + f] = result[f]
    
    output = oldoutput
    localvars = oldlocalvars
    stk = oldstk
    globalvars = oldglobalvars
    globalarrays = oldglobalarrays
    funcs = oldfuncs
    funcpref = oldfuncpref
    tokens = oldtokens
    
    return result

def start(prog, noasm=False, dojzalloc=False):
    global tokens
    global localvars
    global output
    global dataoutput
    global stk
    global ln
    global globalvars
    global globalarrays
    global globalbuffers
    global patternmatches
    global jzalloc
    jzalloc = dojzalloc
    output = ''
    dataoutput = ''
    localvars = {}
    stk = []
    globalvars = {}
    globalarrays = {}
    globalbuffers = {}
    patternmatches = {}
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
        dataout('section .bss')
        for name in globalbuffers.keys():
            nname = globalarrays[name]
            size = globalbuffers[name]
            dataout('{} resb {}'.format(nname, size))
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
    if len(sys.argv) < 2:
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
    print(cresult.dataoutput)
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