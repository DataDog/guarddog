const str = `Y29uc29sZS5sb2coJ2hlbGxvIHdvcmxkJyk7`; // console.log('hello world');
// ruleid: eval-call
eval(atob(str));

// ok: eval-call
eval('console.log(\'hello world\');');

const str2 = 'console.log(\'hello world\');';
// ok: eval-call
eval(str2);
