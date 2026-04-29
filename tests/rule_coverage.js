import child_process from 'child_process';

const userInput = "alert('xss')";

// Express session misconfiguration
session({
  secret: 'test-secret',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
});

// Rule: JS-EVAL-EXEC
eval(userInput);

// Rule: JS-FUNCTION-CONSTRUCTOR
const fn = new Function("a", "b", "return a + b;");
console.log(fn(1, 2));

// Rule: NODE-CHILD-PROCESS-EXEC
child_process.exec("dir " + userInput);
child_process.execFile(userInput);
child_process.execFileSync(userInput);

// Rule: DOM-XSS-DOCUMENT-WRITE
document.write(userInput);

// Rule: DOM-XSS-INNERHTML-ASSIGN
document.body.innerHTML = userInput;

// Rule: DOM-XSS-INSERT-ADJACENT-HTML
document.body.insertAdjacentHTML('beforeend', userInput);

// Rule: JS-STRING-TIMER-EXEC
setTimeout("console.log('timer string')", 1000);
