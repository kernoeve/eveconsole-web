// Is this really a PNG or a JPEG, and how big?
//
// ⚠️ Read from the bytes, never from what the caller says. Only these two types are ever stored,
// and the type they are served as comes from here. Workers cannot decode an image, so this walks
// the file's structure rather than its pixels: it stops a page or a script labelled as a picture,
// not a deliberately damaged picture, which can do no harm served with a fixed type and nosniff.

export interface ImageInfo {
  type: "image/png" | "image/jpeg";
  ext: "png" | "jpg";
  width: number;
  height: number;
}

const MAX_DIMENSION = 12_000;
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

export function inspectImage(bytes: Uint8Array): ImageInfo | null {
  const info = PNG_SIGNATURE.every((b, i) => bytes[i] === b) ? inspectPng(bytes)
    : bytes[0] === 0xff && bytes[1] === 0xd8 ? inspectJpeg(bytes)
    : null;
  if (!info) return null;
  if (info.width < 1 || info.height < 1 || info.width > MAX_DIMENSION || info.height > MAX_DIMENSION) return null;
  return info;
}

/** Walks every chunk: IHDR first, some image data, and IEND exactly at the end of the file. */
function inspectPng(bytes: Uint8Array): ImageInfo | null {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = PNG_SIGNATURE.length;
  let width = 0, height = 0, sawData = false, first = true;

  while (at + 12 <= bytes.length) {
    const length = view.getUint32(at);
    const name = String.fromCharCode(bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]);
    const next = at + 12 + length;
    if (next > bytes.length) return null;

    if (first) {
      if (name !== "IHDR" || length !== 13) return null;
      width = view.getUint32(at + 8);
      height = view.getUint32(at + 12);
      first = false;
    } else if (name === "IDAT") {
      sawData = true;
    } else if (name === "IEND") {
      return sawData && next === bytes.length ? { type: "image/png", ext: "png", width, height } : null;
    }
    at = next;
  }
  return null;
}

/** Walks the segments to the frame header for the size, and requires the end-of-image marker. */
function inspectJpeg(bytes: Uint8Array): ImageInfo | null {
  if (bytes[bytes.length - 2] !== 0xff || bytes[bytes.length - 1] !== 0xd9) return null;

  let at = 2;
  while (at + 4 <= bytes.length) {
    if (bytes[at] !== 0xff) return null;
    while (bytes[at] === 0xff && at < bytes.length) at++;
    const marker = bytes[at++];

    // No length follows these.
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) continue;
    // Image data, or the end, before any frame header: there is no size to read.
    if (marker === 0xda || marker === 0xd9) return null;

    const length = (bytes[at] << 8) | bytes[at + 1];
    if (length < 2 || at + length > bytes.length) return null;

    const isFrame = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
    if (isFrame) {
      if (length < 7) return null;
      return {
        type: "image/jpeg", ext: "jpg",
        height: (bytes[at + 3] << 8) | bytes[at + 4],
        width: (bytes[at + 5] << 8) | bytes[at + 6],
      };
    }
    at += length;
  }
  return null;
}
