import re
import subprocess
import sys

debugerr = True

output = ''
dolnout = False
ln = 1
funcpref = 'func_'
stk = []

funcs = {}
class function:
    def __init__(self, name, args):
        self.name = name
        self.args = args

def tokenize(s):
    s = re.sub(r'#.*\n', '\n', s)
    mcs = r'::|<<|>>|!!|!:|==|!=|<=|>='
    r = mcs + r'|[%@]?[_a-zA-Z]+|\-?[0-9]+|\n[^\S\n]*|\S'
    result = ['\n'] + re.findall(r, s)[::-1]
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

def getok():
    global ln
    try:
        t = tokens.pop()
        while len(t) > 1 and t[0] == '\n':
            ln += 1
            t = getok()
        if t == '\n':
            ln += 1
            if dolnout:
                lnout = ";line {}".format(ln)
                print(lnout)
                out(lnout)
            #out("incrline")
        return t
    except : err("unexpected end of file")
    
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
    if len(s) > 1 and s[0] == '%':
        r = s[1:]
        if not r in allregs : err("no such register ''".format(r))
        return r
    elif s in stk : return 'qword [rsp + {}]'.format(stk[::-1].index(s) * 8)
    elif s in localvars.keys() : return localvars[s]
    elif isint(s) : return s
    elif s == '@retvar' : return retreg
    else : err("could not find var '{}'".format(s))
    

def push(s):
    out('push {}'.format(varloc(s)))
    stk.append(s)

regs = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12',
        'r13', 'r14']
retreg = 'r15'
retvar = '@retvar'
allregs = regs + [retreg]

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

def doop():
    op = getok()
    if toptok() == '[':
        getok()
        var = getvar()
        match(']')
        src = expr()
        out('mov {}, {}'.format(varloc(var), varloc(src)))
    else : var = getvar()
    if toptok() == '[':
        getok()
        while toptok() != ']':
            val = expr()
            out('{} {}, {}'.format(opmap[op], varloc(var), varloc(val)))
        getok()
    else:
        val = expr()
        out('{} {}, {}'.format(opmap[op], varloc(var), varloc(val)))
    return var

def dodivop():
    op = getok()
    var = getvar()
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
    out('idiv rcx')
    om = {'/' : 'rax', '%' : 'rdx'}
    out('mov {}, {}'.format(localvars[var], om[op]))
    l = [va, vc, vd]
    i = 0
    for v in l:
        if v:
            i += 1
            r = localvars[v]
            if r != localvars[var]:
                out('mov {}, {}'.format(r, varloc(v)))
    for a in range(i) : stk.pop()
    out('add rsp, {}'.format(i * 8))
    return var
    """
    if toptok() == '[':
        getok()
        while toptok() != ']':
            val = expr()
            out('{} {}, {}'.format(opmap[op], varloc(var), varloc(val)))
        getok()
    else:
        val = expr()
        out('{} {}, {}'.format(opmap[op], varloc(var), varloc(val)))
    """
    
def dowhile():
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
        if min != None : out('mov {}, {}'.format(varloc(var), varloc(min)))
        out('cmp {}, {}'.format(varloc(var), varloc(max)))
        out('jge {}'.format(exit))
        outlabel(loop)
        expr()
        out('add {}, {}'.format(varloc(var), varloc(inc)))
        out('cmp {}, {}'.format(varloc(var), varloc(max)))
        out('jl {}'.format(loop))
        outlabel(exit)
    else:
        op = getok()
        if not op in compopmap.keys() : expect('comparison operator', op)
        invop = compopinvmap[op]
        var = getreg()
        val = getok()
        cmp = 'cmp {}, {}'.format(varloc(var), varloc(val))
        jmp = '{} {}'.format(compopmap[invop], exit)
        out(cmp)
        out(jmp)
        outlabel(loop)
        expr()
        out(cmp)
        out('{} {}'.format(compopmap[op], loop))
        outlabel(exit)
    return None

def doif():
    exit = newname('exit')
    elsel = newname('else')
    getok()
    iselse = False
    if toptok() == '?' : return dowhile()
    elif toptok() == ':':
        iselse = True
        getok()
    op = getok()
    if not op in compopmap.keys() : expect('comparison operator', op)
    invop = compopinvmap[op]
    var = getreg()
    val = getok()
    cmp = 'cmp {}, {}'.format(varloc(var), varloc(val))
    jmp = '{} {}'.format(compopmap[invop], elsel)
    out(cmp)
    out(jmp)
    expr()
    if iselse:
        out('jmp {}'.format(exit))
    outlabel(elsel)
    if iselse:
        expr()
        outlabel(exit)
    return None

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
    vars = list(localvars.keys())
    if len(arge) > 1 and arge.count(retvar) > 0:
        err("expression in function call arguments not saved to register")
    for v in vars:
        push(v)
    for i in range(len(arge)):
        a = arge[i]        
        r = regs[i]
        out('mov {}, {}'.format(r, varloc(a)))
    out('call {}{}'.format(funcpref, fname))
    for v in vars:
        out('mov {}, {}'.format(localvars[v], varloc(v)))
    for v in vars:
        stk.pop()
    if len(vars) > 0 : out('add rsp, {}'.format(len(vars) * 8))
    return retvar
        
def dolib():
    s = getok()[1:]
    if s == 'm':
        e = expr()
        out('allocmacro {}'.format(varloc(e)))
    elif s == 'f':
        e = expr()
        out('freemacro {}'.format(varloc(e)))
    elif s == 'ret':
        doret()
    return retvar
    
def doassign():
    getok()
    v = getvar()
    times = 1
    off = 0
    if toptok() == '[':
        getok()
        i = expr()
        if toptok() != ']' : times = expr()
        if toptok() != ']' : off = expr()
        match(']')
    else : i = expr()
    e = expr()
    try:
        out('mov qword [{} + {} * {} + {}], {}'.format(varloc(v), varloc(i), times, off, varloc(e)))
    except : err('array assignment error')
    return e
    
def doindex():
    getok()
    a = getvar()
    times = 1 
    off = 0 
    if toptok() == '[': 
        getok() 
        i = expr() 
        if toptok() != ']' : times = expr()
        if toptok() != ']' : off = expr()
        match(']') 
    else : i = expr()
    out('mov {}, qword [{} + {} * {} + {}]'.format(retreg, varloc(a), varloc(i), times, off))
    return retvar

def doret():
    e = expr()
    if not e == retvar : out('mov {}, {}'.format(retreg, varloc(e)))
    out('ret')
    return None

def expr():
    if toptok() in opmap.keys() : return doop()
    elif toptok() in ['/', '%'] : return dodivop()
    elif len(toptok()) > 1 and toptok()[0] == '%' : return getok()
    elif toptok() == '?' : return doif()
    elif toptok()[0] == '@' : return dolib()
    elif toptok() == '!:' : return doassign()
    elif toptok() == '!!' : return doindex()
    elif toptok() == '_i' : return doprinti()
    elif toptok() in funcs.keys() : return docall()
    elif isalnum(toptok()) or isint(toptok()) : return getok()
    elif toptok() == '(':
        getok()
        while toptok() != ')' : last = expr()
        getok()
        return last
    else : err("malformed expression '{}'".format(toptok()))

def startfunc():
    global localvars
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
        val = getint()
        out('mov {}, {}'.format(reg, val))
    getok()
    while toptok() != '\n' : last = expr()
    if last == None : err("must return value at end of function")
    if last != '@retvar' : out('mov {}, {}'.format(retreg, varloc(last)))
    out('ret')
            
def startline():
    startfunc()
    
def findfuncs():
    global tokens
    global ln
    oldtokens = tokens[:]
    while toptok() == '\n' : getok()
    while len(tokens) > 1:
        fname = getid()
        args = []
        locals = []
        while toptok() != '=':
            name = getid()
            args.append(name)
        getok()
        while toptok() != ':':
            name = getid()
            val = getint()
            locals.append(name)
        getok()
        if isint(toptok()) : args.pop()
        funcs[fname] = function(fname, args)
        while toptok() != '\n' : getok()
        while toptok() == '\n' and len(tokens) > 1 : getok()
    tokens = oldtokens
    ln = 1

def start(prog):
    global tokens
    global localvars
    global output
    global stk
    output = ''
    localvars = {}
    stk = []
    tokens = tokenize(prog)
    #print(tokens)
    findfuncs()
    while len(tokens) > 1 and toptok() == '\n' : getok()
    while len(tokens) > 1:
        startline()
        match('\n')
        while len(tokens) > 1 and toptok() == '\n' : getok()
    return output
    
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
       
    output = start(prog)

    comp = compress(prog)

    print(prog + '\n')
    print('Compressed:')
    print(comp + '\n')
    print(output)
    pl = len(prog)
    ol = len(output)
    print("""
    program length: {} chars, {} lines
    assembly length: {}, chars, {} lines
    ratio: {}%
    """.format(pl, len(prog.split('\n')), ol, len(output.split('\n')), int(float(pl) / float(ol) * 100)))

if __name__ == "__main__":
    main()