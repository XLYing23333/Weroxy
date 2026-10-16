const numberText = (value: number) => value.toFixed(Math.abs(value) >= 100 ? 0 : 1).replace(/\.0$/, "");
export function formatBytes(value: number): string {
 if (!Number.isFinite(value)) return "—";
 const units = ["B", "KB", "MB", "GB", "TB"];
 let unit = 0; while (Math.abs(value) >= 1000 && unit < units.length - 1) { value /= 1000; unit++; }
 return `${unit === 0 ? Math.round(value) : numberText(value)} ${units[unit]}`;
}
export function formatCount(value: number): string {
 if (!Number.isFinite(value)) return "—";
 const units = ["", "K", "M", "B"]; let unit=0;
 while (Math.abs(value)>=1000 && unit<units.length-1) {value/=1000;unit++;}
 return `${unit===0 ? Math.round(value) : numberText(value)}${units[unit]}`;
}

export function formatClock(value: string | number, seconds = false): string {
 const date = new Date(value);
 if (!Number.isFinite(date.getTime())) return "—";
 return date.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", ...(seconds ? {second: "2-digit" as const} : {}), hourCycle: "h23"});
}
