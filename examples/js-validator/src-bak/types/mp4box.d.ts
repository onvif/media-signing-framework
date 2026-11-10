// Type definitions for mp4box library
declare module 'mp4box' {
  interface MP4Box {
    createFile(): MP4File;
  }

  interface MP4File {
    onReady?: (info: any) => void;
    onError?: (error: string) => void;
    onSamples?: (id: number, user: any, samples: any[]) => void;
    onEndOfStream?: () => void;
    appendBuffer(data: ArrayBuffer): number;
    start(): void;
    stop(): void;
    flush(): void;
    setExtractionOptions(trackId: number, user: any, options: any): void;
  }

  const MP4Box: MP4Box;
  export default MP4Box;
}
