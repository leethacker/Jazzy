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
    mcs = r'!!|!:|==|!=|<=|>='
    r = mcs + r'|%?[_a-zA-Z]+|\-?[0-9]+|\n[^\S\n]*|\S'
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
    '=' : 'mov',
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

def doop():
    op = getok()
    var = getvar()
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

def dowhile():
    loop = newname('loop')
    exit = newname('exit')
    getok()
    op = getok()
    if not op in compopmap.keys() : expect('comparison operator', op)
    invop = compopinvmap[op]
    var = getvar()
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
    var = getvar()
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
    return '@retvar'
        
def dolib():
    getok()
    s = getid()
    if s == 'm':
        e = expr()
        out('allocmacro {}'.format(varloc(e)))
    elif s == 'f':
        e = expr()
        out('freemacro {}'.format(varloc(e)))
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
    out('mov qword [{} + {} * {} + {}], {}'.format(varloc(v), varloc(i), times, off, varloc(e)))
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

lastret = ''
def expr():
    if toptok() in opmap.keys() : return doop()
    elif len(toptok()) > 1 and toptok()[0] == '%' : return getok()
    elif toptok() == '?' : return doif()
    elif toptok() == '@' : return dolib()
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
    while toptok() != '=':
        name = getid()
        reg = rs.pop()
        localvars[name] = reg
        args.append(name)
    getok()
    while toptok() != ':':
        name = getid()
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
    output = ''
    localvars = {}
    tokens = tokenize(prog)
    #print(tokens)
    findfuncs()
    while len(tokens) > 1 and toptok() == '\n' : getok()
    while len(tokens) > 1:
        startline()
        match('\n')
        while len(tokens) > 1 and toptok() == '\n' : getok()
    return output
    
def main():
    if len(sys.argv) != 2:
        print('wrong number of parameters')
        sys.exit(0)
    prog = open(sys.argv[1]).read()
       
    output = start(prog)

    print(prog + '\n')
    print(output)
    pl = len(prog)
    ol = len(output)
    print("""
    program length: {}
    assembly length: {}
    ratio: {}%
    """.format(pl, ol, int(float(pl) / float(ol) * 100)))

if __name__ == "__main__":
    main()