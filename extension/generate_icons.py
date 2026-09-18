import os
import struct
import zlib

def create_shield_png(width, height):
    """Generate a high-visibility shield icon in RGBA format without third-party dependencies."""
    raw_data = bytearray()
    
    # Colors (RGBA)
    blue = (30, 64, 175, 255)       # #1e40af
    light_blue = (59, 130, 246, 255) # #3b82f6
    white = (255, 255, 255, 255)
    transparent = (0, 0, 0, 0)
    
    cx, cy = width / 2.0, height / 2.0
    
    for y in range(height):
        raw_data.append(0)  # Filter byte for PNG scanline
        ny = (y - cy) / (height / 2.0)
        for x in range(width):
            nx = (x - cx) / (width / 2.0)
            
            # Simple shield curve equation:
            # Top half is boxy with rounded corners, bottom half tapers to point
            in_shield = False
            if ny < 0:
                if abs(nx) <= 0.85 and ny >= -0.85:
                    in_shield = True
            else:
                # Taper towards (0, 0.9)
                taper = 0.85 * (1.0 - (ny ** 1.3))
                if abs(nx) <= taper and ny <= 0.9:
                    in_shield = True
            
            if not in_shield:
                raw_data.extend(transparent)
            else:
                # Border check
                is_border = False
                if abs(nx) > 0.72 or (ny > 0 and abs(nx) > (taper - 0.13)) or ny < -0.75:
                    is_border = True
                
                # Check center symbol (small exclamation mark or check)
                if abs(nx) <= 0.12 and -0.45 <= ny <= 0.05:
                    raw_data.extend(white)
                elif abs(nx) <= 0.12 and 0.22 <= ny <= 0.42:
                    raw_data.extend(white)
                elif is_border:
                    raw_data.extend(light_blue)
                else:
                    raw_data.extend(blue)
                    
    def make_chunk(chunk_type, data):
        length = len(data)
        chunk = chunk_type + data
        crc = zlib.crc32(chunk) & 0xffffffff
        return struct.pack('>I', length) + chunk + struct.pack('>I', crc)
    
    header = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    ihdr = make_chunk(b'IHDR', ihdr_data)
    idat = make_chunk(b'IDAT', zlib.compress(bytes(raw_data)))
    iend = make_chunk(b'IEND', b'')
    
    return header + ihdr + idat + iend

def main():
    icons_dir = os.path.join(os.path.dirname(__file__), "icons")
    os.makedirs(icons_dir, exist_ok=True)
    
    sizes = [16, 48, 128]
    for size in sizes:
        png_bytes = create_shield_png(size, size)
        icon_path = os.path.join(icons_dir, f"icon-{size}.png")
        with open(icon_path, "wb") as f:
            f.write(png_bytes)
        print(f"Generated {icon_path} ({size}x{size})")

if __name__ == "__main__":
    main()
