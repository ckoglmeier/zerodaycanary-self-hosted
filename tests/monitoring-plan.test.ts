import {describe,it,expect} from 'vitest';
import {monitoringState} from '@/lib/monitoring-plan';
describe('workspace allowances',()=>{
 it('retains exactly one free system without a subscription',()=>{expect(monitoringState(null,0,'pending_payment')).toBe('active');expect(monitoringState(null,1,'pending_payment')).toBe('pending_payment');});
 it.each(['active','trialing'])('covers 25 total systems for one unit when %s',status=>{const s={status,quantity:1,billing_model:'workspace'};expect(monitoringState(s,24,'pending_payment')).toBe('active');expect(monitoringState(s,25,'pending_payment')).toBe('pending_payment');});
 it.each(['past_due','unpaid','incomplete','paused','canceled','incomplete_expired'])('keeps free coverage through %s',status=>{const s={status,quantity:1,billing_model:'workspace'};expect(monitoringState(s,0,'payment_issue')).toBe('active');expect(monitoringState(s,1,'active')).toBe('payment_issue');});
 it('never multiplies workspace entitlement by quantity',()=>{expect(monitoringState({status:'active',quantity:2,billing_model:'workspace'},1,'pending_payment')).toBe('pending_payment');});
 it('retains legacy per-system coverage',()=>{const s={status:'active',quantity:2,billing_model:'per_system'};expect(monitoringState(s,1,'pending_payment')).toBe('active');expect(monitoringState(s,2,'pending_payment')).toBe('pending_payment');expect(monitoringState({...s,status:'canceled'},0,'active')).toBe('active');});
});
