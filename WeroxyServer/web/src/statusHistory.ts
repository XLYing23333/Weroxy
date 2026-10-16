import type { StatusPoint } from "./api";
export type StatusBlock = { start: number; end: number; coverage: number; offline: boolean; sessions: number; onlineSeconds: number; observedSeconds: number };
export function statusBlocks(history: StatusPoint[], now=Date.now()): StatusBlock[] {
 const width=300000,end=Math.ceil(now/width)*width,start=end-36*width;
 const points=[...history].filter(p=>Number.isFinite(Date.parse(p.at))).sort((a,b)=>Date.parse(a.at)-Date.parse(b.at));
 return Array.from({length:36},(_,i)=>{
  const a=start+i*width,b=a+width;let observed=0,online=0,sessions=0,offline=false;
  for(let j=0;j<points.length;j++){
   const p=points[j],at=Date.parse(p.at),duration=(p.duration_sec===300?300:60)*1000;
   // A newer observation supersedes the older interval, including background samples.
   // Peaks are observations, including transitions within the same JS millisecond.
   if(at>=a && at<b && at<=now){sessions=Math.max(sessions,p.sessions);if(p.state==="offline")offline=true;}
   const until=Math.min(at+duration,now,j+1<points.length?Date.parse(points[j+1].at):Infinity);
   const overlap=Math.max(0,Math.min(until,b)-Math.max(at,a));if(!overlap)continue;
   observed+=overlap;sessions=Math.max(sessions,p.sessions);if(p.state==="offline")offline=true;else online+=overlap;
  }
  return {start:a,end:b,coverage:Math.min(1,observed/Math.max(1,Math.min(b,now)-a)),offline,sessions,observedSeconds:observed/1000,onlineSeconds:online/1000};
 });
}
