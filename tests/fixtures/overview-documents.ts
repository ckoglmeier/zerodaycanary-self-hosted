import {zipSync,strToU8} from 'fflate';
// Small actual parser fixtures. No real customer documents or model-generated evidence.
export function overviewDocx(text='2024 security review: PHP 8.2.10 and MySQL 8.0.') {
  return zipSync({'word/document.xml':strToU8(`<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${text}</w:t></w:r></w:p></w:body></w:document>`)});
}
export function overviewPdf(text='2024 security review: PHP 8.2.10.',pages=1) {
  const objects=['<< /Type /Catalog /Pages 2 0 R >>',`<< /Type /Pages /Kids [${Array.from({length:pages},(_,i)=>`${4+i*2} 0 R`).join(' ')}] /Count ${pages} >>`,'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'];
  for(let i=0;i<pages;i++) {
    const content=`BT /F1 12 Tf 20 700 Td (${text.replace(/[\\()]/g,'\\$&')}) Tj ET`;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 800] /Resources << /Font << /F1 3 0 R >> >> /Contents ${5+i*2} 0 R >>`,`<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
  }
  let doc='%PDF-1.4\n',offsets=[0];
  for(let i=0;i<objects.length;i++){offsets.push(doc.length);doc+=`${i+1} 0 obj\n${objects[i]}\nendobj\n`;}
  const xref=doc.length;doc+=`xref\n0 ${offsets.length}\n0000000000 65535 f \n`+offsets.slice(1).map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('');
  return Buffer.from(doc+`trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`);
}
