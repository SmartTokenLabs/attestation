
export class Timestamp {
    // Timestamp with millisecond accuracy and timezone info
    // Date.parse('Thu, 01 Jan 1970 00:00:00 GMT-0400');
    // Tue Mar 30 2021 21:14:22 GMT+0300
    public static TIMESTAMP_FORMAT:string = "EEE MMM d yyyy HH:mm:ss 'GMT'Z";
    public ALLOWED_ROUNDING: number = 1000; // 1 sec, since we are always rounding to the nearest second in the string representation

    private time: number;
    private validity: number = 0;

    public constructor(timeSinceEpochInMs:number|string = null) {
        if (!timeSinceEpochInMs) this.time = Date.now();

        if (typeof timeSinceEpochInMs === 'number' ){
            this.time = timeSinceEpochInMs;
        }

        if (typeof timeSinceEpochInMs === 'string' ){
            this.time = Timestamp.stringTimestampToLong(timeSinceEpochInMs);
        }

        this.time = this.time - this.time % 1000;
    }


    public fromString(timeAsString: string) {
        this.time = Timestamp.stringTimestampToLong(timeAsString);
    }

    public getValidity():number {
        return this.validity;
    }

    public setValidity(validity: number) {
        this.validity = validity;
    }

    public getTime(): number {
        return this.time;
    }

    public getTimeAsString(): string {
        let preTime = new Date(this.time).toString();
        return preTime.substr(0, preTime.indexOf('(') - 1);
    }

    public validateTimestamp(): boolean {
        let currentTime = this.getCurrentTime();
        if (this.time > currentTime + this.ALLOWED_ROUNDING) {
            return false;
        }
        // Slack only goes into the future
        if (this.time < currentTime - this.ALLOWED_ROUNDING - this.validity) {
            return false;
        }
        return true;
    }

    public validateAgainstExpiration(expirationTimeInMs: number): boolean {
        let currentTime = this.getCurrentTime();
        // If timestamp is in the future
        if (this.time > (currentTime + this.ALLOWED_ROUNDING)) {
            return false;
        }
        // If token has expired
        if (expirationTimeInMs < (currentTime - this.ALLOWED_ROUNDING)) {
            return false;
        }
        // If the token is valid for too long
        if ((expirationTimeInMs - this.time) > (this.validity + this.ALLOWED_ROUNDING)) {
            return false;
        }
        return true;
    }

    public static stringTimestampToLong(timestamp: string):number {
        return Date.parse(timestamp);
    }

    protected getCurrentTime(): number {
        return Date.now();
    }
}
