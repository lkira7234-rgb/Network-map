import { useMemo, useRef } from 'react'
import * as THREE from 'three'
import { useFrame, type ThreeEvent } from '@react-three/fiber'

/* ------------------------------------------------------------------ */
/*  textures                                                           */
/* ------------------------------------------------------------------ */

let glowTexture: THREE.Texture | null = null

export function getGlowTexture(): THREE.Texture {
  if (glowTexture) return glowTexture
  const size = 256
  const canvas = document.createElement('canvas')
  canvas.width = size
  canvas.height = size
  const ctx = canvas.getContext('2d')!
  const gradient = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2)
  gradient.addColorStop(0, 'rgba(255,255,255,1)')
  gradient.addColorStop(0.18, 'rgba(255,255,255,0.62)')
  gradient.addColorStop(0.45, 'rgba(255,255,255,0.18)')
  gradient.addColorStop(1, 'rgba(255,255,255,0)')
  ctx.fillStyle = gradient
  ctx.fillRect(0, 0, size, size)
  glowTexture = new THREE.CanvasTexture(canvas)
  glowTexture.colorSpace = THREE.SRGBColorSpace
  return glowTexture
}

const labelCache = new Map<string, { texture: THREE.Texture; aspect: number }>()
const labelCenter = new THREE.Vector2(0.5, 0)

function getLabelTexture(text: string, color: string) {
  const key = `${color}|${text}`
  const cached = labelCache.get(key)
  if (cached) return cached

  const fontSize = 48
  const font = `600 ${fontSize}px Rajdhani, "Segoe UI", sans-serif`
  const measure = document.createElement('canvas').getContext('2d')!
  measure.font = font
  const width = Math.ceil(measure.measureText(text).width)

  const canvas = document.createElement('canvas')
  canvas.width = Math.max(32, width + 56)
  canvas.height = 84
  const ctx = canvas.getContext('2d')!
  ctx.font = font
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.shadowColor = color
  ctx.shadowBlur = 22
  ctx.fillStyle = color
  ctx.fillText(text, canvas.width / 2, 44)
  ctx.shadowBlur = 8
  ctx.fillStyle = '#ffffff'
  ctx.globalAlpha = 0.82
  ctx.fillText(text, canvas.width / 2, 44)

  const texture = new THREE.CanvasTexture(canvas)
  texture.colorSpace = THREE.SRGBColorSpace
  texture.minFilter = THREE.LinearFilter
  texture.magFilter = THREE.LinearFilter
  const entry = { texture, aspect: canvas.width / canvas.height }
  labelCache.set(key, entry)
  return entry
}

/* ------------------------------------------------------------------ */
/*  primitives                                                         */
/* ------------------------------------------------------------------ */

interface GlowProps {
  color: string
  scale: number
  position?: [number, number, number]
  opacity?: number
}

export function Glow({ color, scale, position = [0, 0, 0], opacity = 0.75 }: GlowProps) {
  const texture = useMemo(() => getGlowTexture(), [])
  return (
    <sprite position={position} scale={[scale, scale, 1]} renderOrder={2}>
      <spriteMaterial
        map={texture}
        color={color}
        transparent
        opacity={opacity}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
        toneMapped={false}
      />
    </sprite>
  )
}

interface LabelProps {
  text: string
  color: string
  position?: [number, number, number]
  scale?: number
  opacity?: number
  anchor?: boolean
}

export function Label({ text, color, position = [0, 0, 0], scale = 1, opacity = 1 }: LabelProps) {
  const { texture, aspect } = useMemo(() => getLabelTexture(text, color), [text, color])
  const height = 0.72 * scale
  const width = height * aspect
  return (
    <sprite position={position} scale={[width, height, 1]} center={labelCenter} renderOrder={20} raycast={() => undefined}>
      <spriteMaterial
        map={texture}
        transparent
        opacity={opacity}
        depthWrite={false}
        depthTest={false}
        toneMapped={false}
      />
    </sprite>
  )
}

/* ------------------------------------------------------------------ */
/*  animated packets                                                   */
/* ------------------------------------------------------------------ */

interface FlowingDotsProps {
  points: THREE.Vector3[]
  color: string
  count?: number
  speed?: number
  radius?: number
}

export function FlowingDots({ points, color, count = 3, speed = 0.09, radius = 0.1 }: FlowingDotsProps) {
  const curve = useMemo(() => {
    if (points.length < 2) return null
    return new THREE.CatmullRomCurve3(points, false, 'catmullrom', 0.28)
  }, [points])

  const refs = useRef<(THREE.Mesh | null)[]>([])
  const offsets = useMemo(
    () => Array.from({ length: count }, (_, i) => (i / count + Math.random() * 0.12) % 1),
    [count],
  )

  useFrame(({ clock }) => {
    if (!curve) return
    const t0 = clock.getElapsedTime() * speed
    refs.current.forEach((mesh, i) => {
      if (!mesh) return
      const t = (t0 + offsets[i]) % 1
      curve.getPointAt(t, mesh.position)
    })
  })

  if (!curve) return null

  return (
    <group>
      {Array.from({ length: count }, (_, i) => (
        <mesh
          key={i}
          ref={(el) => {
            refs.current[i] = el
          }}
        >
          <sphereGeometry args={[radius, 8, 8]} />
          <meshBasicMaterial color={color} transparent opacity={0.92} toneMapped={false} />
        </mesh>
      ))}
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  interaction helpers                                                */
/* ------------------------------------------------------------------ */

export function useHoverHandlers(onHover: (text: string | null) => void, text: string) {
  return useMemo(
    () => ({
      onPointerOver: (event: ThreeEvent<PointerEvent>) => {
        event.stopPropagation()
        onHover(text)
        document.body.style.cursor = 'pointer'
      },
      onPointerOut: (event: ThreeEvent<PointerEvent>) => {
        event.stopPropagation()
        onHover(null)
        document.body.style.cursor = 'default'
      },
    }),
    [onHover, text],
  )
}