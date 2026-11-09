import{describe,it,expect,vi}from'vitest';
vi.mock('server-only',()=>({}));
import{workspaceName}from'@/lib/workspace';
describe('requester organization names',()=>{
 it('preserves the supplied name while trimming surrounding spaces',()=>expect(workspaceName.parse('  Cedar College  ')).toBe('Cedar College'));
 it.each(['',' ','A','x'.repeat(121),'Buyer\nBcc: other','Buyer\u0000Name'])('rejects missing, excessive or multiline names',name=>expect(workspaceName.safeParse(name).success).toBe(false));
});
