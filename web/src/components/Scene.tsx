import { useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import { Canvas, useFrame, useThree, type ThreeEvent } from '@react-three/fiber'
import { Grid, Line, OrbitControls } from '@react-three/drei'
import { Bloom, EffectComposer, Vignette } from '@react-three/postprocessing'
import { ScanState, Selection, SubdomainInfo } from '../types'
import {
  CORE_Y,
  ClusterLayout,
  ClusterMode,
  DnsNodeLayout,
  HopLayout,
  IpLayout,
  buildLayout,
  buildSubdomainLayout,
  ipLinkPoints,
  shortName,
} from '../layout'
import { FlowingDots, Glow, Label, getGlowTexture, useHoverHandlers } from '../visuals'
import { FlyControls } from './FlyControls'
import { collectCves, cveKey, cvePortSet } from '../cve'

interface SceneProps {
  model: ScanState
  selection: Selection
  onSelect: (selection: Selection) => void
  onHover: (text: string | null) => void
  mode: 'orbit' | 'fly'
  onExitFly: () => void
  resetSignal: number
  cluster: ClusterMode
  subdomains: SubdomainInfo[]
  focusIps: string[]
  focusSignal: number
  onScanSubdomain: (name: string) => void
  /** Trash Mode is picking a random target: show the debris cloud. */
  trashMode?: boolean
  /** Increment to trigger the cinematic warp fly-through. */
  warpSignal?: number
}

export function Scene(props: SceneProps) {
  return (
    <div className="scene" id="scene">
      <Canvas
        dpr={[1, 1.8]}
        gl={{ antialias: true, powerPreference: 'high-performance' }}
        camera={{ position: [0, 25, 54], fov: 48, near: 0.1, far: 500 }}
        onPointerMissed={() => props.onSelect(null)}
      >
        <SceneContent {...props} />
      </Canvas>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  scene root                                                         */
/* ------------------------------------------------------------------ */

function SceneContent({
  model,
  selection,
  onSelect,
  onHover,
  mode,
  onExitFly,
  resetSignal,
  cluster,
  subdomains,
  focusIps,
  focusSignal,
  onScanSubdomain,
  trashMode = false,
  warpSignal = 0,
}: SceneProps) {
  const layout = useMemo(
    () => buildLayout(model, cluster),
    [model.ips, model.hops, model.dns, cluster],
  )
  const scanning = model.phase === 'scanning'
  const hasData = model.ips.length > 0
  const cves = useMemo(() => collectCves(model), [model.ips])
  const vulnerablePorts = useMemo(() => cvePortSet(cves), [cves])
  const vulnerableIps = useMemo(() => new Set(cves.map((match) => match.ip)), [cves])
  const [warping, setWarping] = useState(false)

  // Keep the effect on long enough for the camera to finish its dive.
  useEffect(() => {
    if (!warpSignal) return
    setWarping(true)
    const id = window.setTimeout(() => setWarping(false), 2700)
    return () => window.clearTimeout(id)
  }, [warpSignal])

  const focusSet = useMemo(
    () => (focusIps.length ? new Set(focusIps) : null),
    [focusIps],
  )
  const focusPoints = useMemo(
    () =>
      focusSet
        ? layout.ips.filter((node) => focusSet.has(node.entry.ip)).map((node) => node.pos)
        : [],
    [layout, focusSet],
  )
  const subLayout = useMemo(() => buildSubdomainLayout(subdomains.slice(0, 60).map((item) => item.name)), [subdomains])

  return (
    <>
      <color attach="background" args={['#02030a']} />
      <fog attach="fog" args={['#02030a', 62, 210]} />

      <ambientLight intensity={0.55} color="#7ad7ff" />
      <pointLight position={[0, 30, 24]} intensity={260} distance={110} decay={2} color="#ff2fd6" />
      <pointLight position={[-24, 14, -16]} intensity={180} distance={90} decay={2} color="#38f6ff" />
      <pointLight position={[24, 6, 18]} intensity={120} distance={80} decay={2} color="#8b5cff" />

      <CameraRig
        mode={mode}
        onExitFly={onExitFly}
        resetSignal={resetSignal}
        hasSelection={selection != null}
        focusPoints={focusPoints}
        focusSignal={focusSignal}
        warpSignal={warpSignal}
        warping={warping}
      />

      <Starfield />
      <DustField />
      <GroundGrid />
      <RadarRings />
      <OrbitalShell />
      <JunkCloud active={trashMode} warping={warping} />
      <WarpLines active={warping} />

      <CoreNode
        model={model}
        layout={layout}
        selected={selection?.kind === 'core'}
        onSelect={onSelect}
        onHover={onHover}
      />

      {layout.clusters.map((group) => (
        <ClusterShell key={`cluster-${group.key}`} group={group} />
      ))}

      {hasData &&
        layout.ips.map((node) => (
          <IpSystem
            key={node.entry.ip}
            node={node}
            selection={selection}
            onSelect={onSelect}
            onHover={onHover}
            vulnerablePorts={vulnerablePorts}
            vulnerable={vulnerableIps.has(node.entry.ip)}
            dimmed={Boolean(focusSet && !focusSet.has(node.entry.ip))}
          />
        ))}

      {hasData &&
        layout.ips.map((node) => (
          <IpLink
            key={`link-${node.entry.ip}`}
            from={layout.core}
            to={node.pos}
            color="#38f6ff"
            ip={node.entry.ip}
            onSelect={onSelect}
            onHover={onHover}
            dimmed={Boolean(focusSet && !focusSet.has(node.entry.ip))}
          />
        ))}

      {subLayout.map((node) => (
        <SubdomainLink key={`sub-link-${node.name}`} from={layout.core} to={node.pos} />
      ))}
      {subLayout.map((node) => (
        <SubdomainNode
          key={`sub-${node.name}`}
          name={node.name}
          position={node.pos}
          onScan={onScanSubdomain}
          onHover={onHover}
        />
      ))}

      {hasData && (
        <Line
          points={[layout.you, layout.core]}
          color="#38f6ff"
          lineWidth={0.7}
          dashed
          dashSize={0.8}
          gapSize={0.7}
          transparent
          opacity={0.14}
        />
      )}

      {layout.ns.map((node, index) => (
        <DnsLink key={`ns-link-${node.name}-${index}`} from={layout.core} to={node.pos} kind="ns" />
      ))}
      {layout.mx.map((node, index) => (
        <DnsLink key={`mx-link-${node.name}-${index}`} from={layout.core} to={node.pos} kind="mx" />
      ))}

      {layout.ns.map((node, index) => (
        <DnsNode
          key={`ns-${node.name}-${index}`}
          node={node}
          kind="ns"
          index={index}
          selected={selection?.kind === 'ns' && selection.index === index}
          onSelect={onSelect}
          onHover={onHover}
        />
      ))}
      {layout.mx.map((node, index) => (
        <DnsNode
          key={`mx-${node.name}-${index}`}
          node={node}
          kind="mx"
          index={index}
          selected={selection?.kind === 'mx' && selection.index === index}
          onSelect={onSelect}
          onHover={onHover}
        />
      ))}

      {layout.hops.length > 0 && (
        <>
          <Line
            points={layout.hopLine}
            color="#ff2bd6"
            lineWidth={1.5}
            transparent
            opacity={0.38}
            toneMapped={false}
          />
          <FlowingDots points={layout.hopLine} color="#ffb020" count={6} speed={0.045} radius={0.1} />
        </>
      )}

      {layout.hops.map((node) => (
        <HopNode
          key={`hop-${node.hop.index}`}
          node={node}
          selected={selection?.kind === 'hop' && selection.index === node.hop.index}
          onSelect={onSelect}
          onHover={onHover}
        />
      ))}

      <YouNode
        position={layout.you}
        selected={selection?.kind === 'you'}
        onSelect={onSelect}
        onHover={onHover}
      />

      {scanning && <ScanPulse position={layout.core} />}

      <EffectComposer multisampling={0}>
        <Bloom intensity={1.05} luminanceThreshold={0.18} luminanceSmoothing={0.3} mipmapBlur />
        <Vignette eskil={false} offset={0.18} darkness={0.82} />
      </EffectComposer>
    </>
  )
}

/* ------------------------------------------------------------------ */
/*  camera                                                             */
/* ------------------------------------------------------------------ */

function CameraRig({
  mode,
  onExitFly,
  resetSignal,
  hasSelection,
  focusPoints,
  focusSignal,
  warpSignal,
  warping,
}: {
  mode: 'orbit' | 'fly'
  onExitFly: () => void
  resetSignal: number
  hasSelection: boolean
  focusPoints: THREE.Vector3[]
  focusSignal: number
  warpSignal: number
  warping: boolean
}) {
  const controls = useRef<any>(null)
  const camera = useThree((state) => state.camera) as THREE.PerspectiveCamera
  const desired = useRef(new THREE.Vector3(0, CORE_Y, 0))
  const offset = useRef(new THREE.Vector3(0, 8, 24))
  const flying = useRef(false)
  const warp = useRef<{ at: number; from: THREE.Vector3 } | null>(null)
  const BASE_FOV = 48
  const WARP_MS = 2400

  useEffect(() => {
    if (!resetSignal) return
    camera.position.set(0, 25, 54)
    camera.lookAt(0, CORE_Y, 0)
    camera.fov = BASE_FOV
    camera.updateProjectionMatrix()
    warp.current = null
    flying.current = false
    if (controls.current) {
      controls.current.target.set(0, CORE_Y, 0)
      controls.current.update()
    }
  }, [resetSignal, camera])

  // A warp starts from wherever the camera currently is and dives through the
  // debris cloud into the target core.
  useEffect(() => {
    if (!warpSignal) return
    warp.current = { at: performance.now(), from: camera.position.clone() }
    flying.current = false
  }, [warpSignal, camera])

  useEffect(() => {
    if (warping) return
    warp.current = null
    camera.fov = BASE_FOV
    camera.updateProjectionMatrix()
  }, [warping, camera])

  useEffect(() => {
    if (!focusPoints.length) {
      flying.current = false
      return
    }
    const center = focusPoints
      .reduce((acc, point) => acc.add(point), new THREE.Vector3())
      .multiplyScalar(1 / focusPoints.length)
    let spread = 0
    for (const point of focusPoints) spread = Math.max(spread, point.distanceTo(center))
    const distance = Math.max(16, Math.min(58, 21 + spread * 1.7))
    desired.current.copy(center)
    offset.current.set(0, distance * 0.34, distance)
    flying.current = true
  }, [focusSignal, focusPoints])

  useFrame(() => {
    const control = controls.current

    if (warp.current) {
      const t = Math.min(1, (performance.now() - warp.current.at) / WARP_MS)
      // Ease-out so the last metres feel like the camera is braking.
      const ease = 1 - Math.pow(1 - t, 2.6)
      const goal = new THREE.Vector3(0, CORE_Y + 8, 24)
      const pos = warp.current.from.clone().lerp(goal, ease)
      const swirl = (1 - t) * 9
      pos.x += Math.sin(t * Math.PI * 3.4) * swirl
      pos.y += Math.cos(t * Math.PI * 2.2) * swirl * 0.5
      camera.position.copy(pos)
      camera.lookAt(0, CORE_Y, 0)
      camera.fov = BASE_FOV + Math.sin(t * Math.PI) * 34
      camera.updateProjectionMatrix()
      if (t >= 1) {
        warp.current = null
        camera.fov = BASE_FOV
        camera.updateProjectionMatrix()
        if (control) {
          control.target.set(0, CORE_Y, 0)
          control.update()
        }
      }
      return
    }

    if (!flying.current || !control) return
    control.target.lerp(desired.current, 0.09)
    const goal = desired.current.clone().add(offset.current)
    camera.position.lerp(goal, 0.065)
    control.update()
    if (camera.position.distanceTo(goal) < 0.5) flying.current = false
  })

  return (
    <>
      <OrbitControls
        ref={controls}
        enabled={mode === 'orbit' && !warping}
        target={[0, CORE_Y, 0]}
        enableDamping
        dampingFactor={0.06}
        rotateSpeed={0.7}
        zoomSpeed={0.85}
        panSpeed={0.6}
        minDistance={8}
        maxDistance={165}
        maxPolarAngle={Math.PI * 0.495}
        autoRotate={mode === 'orbit' && !hasSelection && !warping}
        autoRotateSpeed={0.3}
        onStart={() => {
          if (warp.current) return
          flying.current = false
        }}
      />
      <FlyControls enabled={mode === 'fly'} onExit={onExitFly} />
    </>
  )
}


/* ------------------------------------------------------------------ */
/*  environment                                                        */
/* ------------------------------------------------------------------ */

function Starfield() {
  const { cyan, magenta } = useMemo(() => {
    let seed = 1337
    const rand = () => {
      seed = (seed * 1664525 + 1013904223) % 4294967296
      return seed / 4294967296
    }
    const make = (count: number, radius: number) => {
      const arr = new Float32Array(count * 3)
      for (let i = 0; i < count; i++) {
        const r = radius + rand() * 120
        const theta = rand() * Math.PI * 2
        const phi = Math.acos(2 * rand() - 1)
        arr[i * 3] = Math.sin(phi) * Math.cos(theta) * r
        arr[i * 3 + 1] = Math.cos(phi) * r * 0.7 + 45
        arr[i * 3 + 2] = Math.sin(phi) * Math.sin(theta) * r
      }
      return arr
    }
    return { cyan: make(1400, 90), magenta: make(420, 130) }
  }, [])

  return (
    <group>
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[cyan, 3]} />
        </bufferGeometry>
        <pointsMaterial
          color="#2e8fb0"
          size={0.42}
          sizeAttenuation
          transparent
          opacity={0.7}
          depthWrite={false}
          fog={false}
          toneMapped={false}
        />
      </points>
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[magenta, 3]} />
        </bufferGeometry>
        <pointsMaterial
          color="#b32a86"
          size={0.5}
          sizeAttenuation
          transparent
          opacity={0.55}
          depthWrite={false}
          fog={false}
          toneMapped={false}
        />
      </points>
    </group>
  )
}

function DustField() {
  const group = useRef<THREE.Group>(null)
  const positions = useMemo(() => {
    let seed = 99
    const rand = () => {
      seed = (seed * 1664525 + 1013904223) % 4294967296
      return seed / 4294967296
    }
    const arr = new Float32Array(420 * 3)
    for (let i = 0; i < 420; i++) {
      const angle = rand() * Math.PI * 2
      const radius = 6 + rand() * 48
      arr[i * 3] = Math.cos(angle) * radius
      arr[i * 3 + 1] = rand() * 42
      arr[i * 3 + 2] = Math.sin(angle) * radius
    }
    return arr
  }, [])

  useFrame((_, delta) => {
    if (group.current) group.current.rotation.y += delta * 0.012
  })

  return (
    <group ref={group}>
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[positions, 3]} />
        </bufferGeometry>
        <pointsMaterial
          color="#54d6ff"
          size={0.12}
          sizeAttenuation
          transparent
          opacity={0.28}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
          toneMapped={false}
        />
      </points>
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  trash-mode debris cloud & warp lines                               */
/* ------------------------------------------------------------------ */

const JUNK_PALETTE = ['#8a4a22', '#c46a2d', '#ff8a3d', '#5b5b62', '#7a7368', '#a39a8c']

function JunkCloud({ active, warping }: { active: boolean; warping: boolean }) {
  const group = useRef<THREE.Group>(null)

  const { positions, colors } = useMemo(() => {
    let seed = 4242
    const rand = () => {
      seed = (seed * 1664525 + 1013904223) % 4294967296
      return seed / 4294967296
    }
    const count = 1100
    const pos = new Float32Array(count * 3)
    const col = new Float32Array(count * 3)
    const palette = JUNK_PALETTE.map((value) => new THREE.Color(value))
    for (let i = 0; i < count; i++) {
      const angle = rand() * Math.PI * 2
      // A torn ring rather than a sphere: debris drifts around the map plane.
      const radius = 16 + Math.pow(rand(), 0.72) * 76
      const y = (rand() - 0.32) * (12 + radius * 0.7)
      pos[i * 3] = Math.cos(angle) * radius
      pos[i * 3 + 1] = y
      pos[i * 3 + 2] = Math.sin(angle) * radius
      const tint = palette[Math.floor(rand() * palette.length)]
      const dim = 0.45 + rand() * 0.55
      col[i * 3] = tint.r * dim
      col[i * 3 + 1] = tint.g * dim
      col[i * 3 + 2] = tint.b * dim
    }
    return { positions: pos, colors: col }
  }, [])

  useFrame((_, delta) => {
    if (!group.current) return
    group.current.rotation.y += delta * (warping ? 0.9 : 0.045)
    group.current.rotation.x = Math.sin(performance.now() * 0.00006) * 0.06
  })

  return (
    <group ref={group} visible={active || warping}>
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[positions, 3]} />
          <bufferAttribute attach="attributes-color" args={[colors, 3]} />
        </bufferGeometry>
        <pointsMaterial
          vertexColors
          size={warping ? 0.52 : 0.34}
          sizeAttenuation
          transparent
          opacity={warping ? 0.95 : 0.62}
          depthWrite={false}
          toneMapped={false}
        />
      </points>
      <points rotation={[0.7, 1.9, 0]}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[positions, 3]} />
        </bufferGeometry>
        <pointsMaterial
          color="#c46a2d"
          size={warping ? 0.9 : 0.6}
          sizeAttenuation
          transparent
          opacity={warping ? 0.42 : 0.22}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
          toneMapped={false}
        />
      </points>
      {/* a few larger rusty shards */}
      {Array.from({ length: 12 }).map((_, index) => {
        const angle = (index / 12) * Math.PI * 2 + 0.4
        const radius = 22 + ((index * 13) % 46)
        return (
          <mesh
            key={`shard-${index}`}
            position={[Math.cos(angle) * radius, ((index % 5) - 2) * 7, Math.sin(angle) * radius]}
            rotation={[index * 0.7, index * 0.4, index * 0.9]}
          >
            <tetrahedronGeometry args={[0.55 + (index % 3) * 0.35, 0]} />
            <meshBasicMaterial
              color={index % 2 === 0 ? '#8a4a22' : '#5b5b62'}
              transparent
              opacity={warping ? 0.75 : 0.45}
              wireframe={index % 3 === 0}
              toneMapped={false}
            />
          </mesh>
        )
      })}
    </group>
  )
}

function WarpLines({ active }: { active: boolean }) {
  const ref = useRef<THREE.LineSegments>(null)
  const geometry = useMemo(() => {
    const geo = new THREE.BufferGeometry()
    let seed = 777
    const rand = () => {
      seed = (seed * 1664525 + 1013904223) % 4294967296
      return seed / 4294967296
    }
    const count = 140
    const arr = new Float32Array(count * 6)
    for (let i = 0; i < count; i++) {
      const angle = rand() * Math.PI * 2
      const radius = 4 + rand() * 62
      const x = Math.cos(angle) * radius
      const y = (rand() - 0.35) * 46
      const z = -190 + rand() * 230
      const length = 5 + rand() * 18
      arr[i * 6] = x
      arr[i * 6 + 1] = y
      arr[i * 6 + 2] = z
      arr[i * 6 + 3] = x
      arr[i * 6 + 4] = y
      arr[i * 6 + 5] = z + length
    }
    geo.setAttribute('position', new THREE.BufferAttribute(arr, 3))
    return geo
  }, [])

  useFrame((_, delta) => {
    if (!active) return
    const attribute = geometry.getAttribute('position') as THREE.BufferAttribute
    const arr = attribute.array as Float32Array
    const speed = delta * 190
    for (let i = 0; i < arr.length; i += 6) {
      arr[i + 2] += speed
      arr[i + 5] += speed
      if (arr[i + 2] > 90) {
        arr[i + 2] -= 300
        arr[i + 5] -= 300
      }
    }
    attribute.needsUpdate = true
    if (ref.current) ref.current.rotation.z += delta * 0.06
  })

  return (
    <lineSegments ref={ref} geometry={geometry} visible={active}>
      <lineBasicMaterial color="#ff8a3d" transparent opacity={0.55} depthWrite={false} toneMapped={false} />
    </lineSegments>
  )
}

function GroundGrid() {
  const texture = useMemo(() => getGlowTexture(), [])
  return (
    <>
      <Grid
        position={[0, 0, 0]}
        args={[240, 240]}
        cellSize={2}
        cellThickness={0.55}
        cellColor="#0c3444"
        sectionSize={10}
        sectionThickness={1.1}
        sectionColor="#16748d"
        fadeDistance={165}
        fadeStrength={1.6}
        infiniteGrid
        followCamera={false}
      />
      <mesh rotation-x={-Math.PI / 2} position={[0, 0.04, 0]} scale={[52, 52, 1]}>
        <planeGeometry args={[1, 1]} />
        <meshBasicMaterial
          map={texture}
          color="#0c7d93"
          transparent
          opacity={0.3}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
          toneMapped={false}
        />
      </mesh>
    </>
  )
}

function RadarRings() {
  return (
    <group position={[0, 0.06, 0]}>
      {[10, 18, 27, 37].map((radius, index) => (
        <mesh key={radius} rotation-x={-Math.PI / 2}>
          <ringGeometry args={[radius, radius + 0.04, 160]} />
          <meshBasicMaterial
            color={index % 2 === 0 ? '#16748d' : '#62306b'}
            transparent
            opacity={0.22}
            side={THREE.DoubleSide}
            depthWrite={false}
            toneMapped={false}
          />
        </mesh>
      ))}
    </group>
  )
}

function OrbitalShell() {
  const inner = useRef<THREE.Mesh>(null)
  const outer = useRef<THREE.Mesh>(null)

  useFrame(({ clock }) => {
    const t = clock.elapsedTime
    if (inner.current) {
      inner.current.rotation.y = t * 0.04
      inner.current.rotation.x = Math.sin(t * 0.08) * 0.15
    }
    if (outer.current) {
      outer.current.rotation.y = -t * 0.025
      outer.current.rotation.z = Math.cos(t * 0.06) * 0.2
    }
  })

  return (
    <group position={[0, CORE_Y, 0]}>
      <mesh ref={inner}>
        <icosahedronGeometry args={[27, 1]} />
        <meshBasicMaterial color="#1a5d74" wireframe transparent opacity={0.06} toneMapped={false} />
      </mesh>
      <mesh ref={outer} rotation={[0.4, 0, 0.2]}>
        <torusGeometry args={[33, 0.02, 6, 220]} />
        <meshBasicMaterial color="#8a2f74" transparent opacity={0.28} toneMapped={false} />
      </mesh>
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  core                                                               */
/* ------------------------------------------------------------------ */

function CoreNode({
  model,
  layout,
  selected,
  onSelect,
  onHover,
}: {
  model: ScanState
  layout: ReturnType<typeof buildLayout>
  selected: boolean
  onSelect: (selection: Selection) => void
  onHover: (text: string | null) => void
}) {
  const core = useRef<THREE.Group>(null)
  const solid = useRef<THREE.Mesh>(null)
  const ringA = useRef<THREE.Mesh>(null)
  const ringB = useRef<THREE.Mesh>(null)
  const ringC = useRef<THREE.Mesh>(null)
  const scanning = model.phase === 'scanning'

  const handlers = useHoverHandlers(onHover, model.host ? `CORE · ${model.host}` : 'TARGET CORE · idle')
  const onClick = (event: ThreeEvent<MouseEvent>) => {
    event.stopPropagation()
    onSelect({ kind: 'core' })
  }

  useFrame(({ clock }) => {
    const t = clock.elapsedTime
    const speed = scanning ? 1.8 : 0.45
    if (solid.current) {
      solid.current.rotation.y = t * speed * 0.5
      solid.current.rotation.x = Math.sin(t * 0.4) * 0.2
    }
    if (ringA.current) ringA.current.rotation.z = t * speed
    if (ringB.current) {
      ringB.current.rotation.z = -t * speed * 0.72
      ringB.current.rotation.x = Math.PI / 2 + Math.sin(t * 0.3) * 0.25
    }
    if (ringC.current) ringC.current.rotation.y = t * speed * 0.45
    if (core.current) {
      const base = selected ? 1.16 : 1
      const pulse = 1 + Math.sin(t * (scanning ? 4 : 1.8)) * 0.035
      core.current.scale.setScalar(base * pulse)
    }
  })

  const title = model.host ? shortName(model.host, 30) : 'NO TARGET'
  const primary = model.ips.find((ip) => ip.primary) || model.ips[0]

  return (
    <group position={layout.core} ref={core}>
      <mesh ref={solid} {...handlers} onClick={onClick}>
        <icosahedronGeometry args={[1.7, 1]} />
        <meshBasicMaterial color="#ff2fd6" wireframe transparent opacity={0.92} toneMapped={false} />
      </mesh>
      <mesh scale={0.72}>
        <icosahedronGeometry args={[1.7, 0]} />
        <meshBasicMaterial color="#ff2fd6" transparent opacity={0.16} toneMapped={false} />
      </mesh>

      <mesh rotation={[Math.PI / 2, 0, 0]} ref={ringA}>
        <torusGeometry args={[2.9, 0.022, 8, 140]} />
        <meshBasicMaterial color="#ff5ee4" transparent opacity={0.85} toneMapped={false} />
      </mesh>
      <mesh ref={ringB} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[3.7, 0.016, 8, 150]} />
        <meshBasicMaterial color="#ffb020" transparent opacity={0.55} toneMapped={false} />
      </mesh>
      <mesh ref={ringC} rotation={[0.4, 0, 0.6]}>
        <torusGeometry args={[4.5, 0.012, 6, 160]} />
        <meshBasicMaterial color="#38f6ff" transparent opacity={0.4} toneMapped={false} />
      </mesh>

      {selected && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[5.4, 0.03, 8, 160]} />
          <meshBasicMaterial color="#ffffff" transparent opacity={0.8} toneMapped={false} />
        </mesh>
      )}

      <Glow color="#ff2fd6" scale={13} opacity={0.5} />
      <Glow color="#38f6ff" scale={5.5} opacity={0.32} />

      <mesh
        {...handlers}
        onClick={onClick}
        scale={2.4}
      >
        <sphereGeometry args={[1, 16, 16]} />
        <meshBasicMaterial transparent opacity={0} depthWrite={false} />
      </mesh>

      <Label text={title} color="#ff7bea" position={[0, 3.9, 0]} scale={1.7} />
      <Label
        text={primary ? primary.ip : scanning ? 'RESOLVING…' : 'AWAITING SIGNAL'}
        color="#7fe9ff"
        position={[0, 3.06, 0]}
        scale={0.95}
        opacity={0.85}
      />
      <mesh position={[0, -5, 0]}>
        <cylinderGeometry args={[0.06, 0.06, 10, 8]} />
        <meshBasicMaterial
          color="#ff2fd6"
          transparent
          opacity={0.24}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
          toneMapped={false}
        />
      </mesh>
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  IP systems                                                         */
/* ------------------------------------------------------------------ */

function IpLink({
  from,
  to,
  color,
  ip,
  onSelect,
  onHover,
  dimmed,
}: {
  from: THREE.Vector3
  to: THREE.Vector3
  color: string
  ip: string
  onSelect: (selection: Selection) => void
  onHover: (text: string | null) => void
  dimmed: boolean
}) {
  const points = useMemo(() => ipLinkPoints(from, to), [from, to])
  const { mid, quaternion, length } = useMemo(() => {
    const direction = to.clone().sub(from)
    return {
      mid: from.clone().add(to).multiplyScalar(0.5),
      quaternion: new THREE.Quaternion().setFromUnitVectors(
        new THREE.Vector3(0, 1, 0),
        direction.clone().normalize(),
      ),
      length: direction.length(),
    }
  }, [from, to])
  const handlers = useHoverHandlers(onHover, `${ip} · link · клик — пакет обмена`)

  return (
    <>
      <Line
        points={points}
        color={color}
        lineWidth={1}
        transparent
        opacity={dimmed ? 0.05 : 0.32}
        toneMapped={false}
      />
      {!dimmed && <FlowingDots points={points} color={color} count={3} speed={0.14} radius={0.08} />}
      <mesh
        position={mid}
        quaternion={quaternion}
        {...handlers}
        onClick={(event) => {
          event.stopPropagation()
          onSelect({ kind: 'link', ip })
        }}
      >
        <cylinderGeometry args={[0.55, 0.55, length, 6]} />
        <meshBasicMaterial transparent opacity={0} depthWrite={false} />
      </mesh>
    </>
  )
}

function ClusterShell({ group }: { group: ClusterLayout }) {
  return (
    <group position={group.pos}>
      <mesh>
        <sphereGeometry args={[group.radius, 20, 14]} />
        <meshBasicMaterial color="#38f6ff" wireframe transparent opacity={0.06} depthWrite={false} toneMapped={false} />
      </mesh>
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <ringGeometry args={[group.radius, group.radius + 0.06, 96]} />
        <meshBasicMaterial
          color="#8b5cff"
          transparent
          opacity={0.25}
          side={THREE.DoubleSide}
          depthWrite={false}
          toneMapped={false}
        />
      </mesh>
      <Label
        text={`${group.label} · ${group.count}`}
        color="#9ad8ff"
        position={[0, group.radius + 0.9, 0]}
        scale={0.86}
        opacity={0.8}
      />
    </group>
  )
}

function SubdomainLink({ from, to }: { from: THREE.Vector3; to: THREE.Vector3 }) {
  const points = useMemo(() => [from, to], [from, to])
  return (
    <Line
      points={points}
      color="#8b5cff"
      lineWidth={0.6}
      dashed
      dashSize={0.45}
      gapSize={0.45}
      transparent
      opacity={0.16}
      toneMapped={false}
    />
  )
}

function SubdomainNode({
  name,
  position,
  onScan,
  onHover,
}: {
  name: string
  position: THREE.Vector3
  onScan: (name: string) => void
  onHover: (text: string | null) => void
}) {
  const mesh = useRef<THREE.Mesh>(null)
  const handlers = useHoverHandlers(onHover, `CT · ${name} · клик — быстрый скан`)

  useFrame(({ clock }) => {
    if (!mesh.current) return
    mesh.current.rotation.y = clock.elapsedTime * 0.6
    mesh.current.rotation.x = Math.sin(clock.elapsedTime * 0.5) * 0.25
  })

  return (
    <group position={position}>
      <mesh
        ref={mesh}
        {...handlers}
        onClick={(event) => {
          event.stopPropagation()
          onScan(name)
        }}
      >
        <octahedronGeometry args={[0.34, 0]} />
        <meshBasicMaterial color="#a48bff" wireframe transparent opacity={0.92} toneMapped={false} />
      </mesh>
      <mesh scale={0.3}>
        <octahedronGeometry args={[0.34, 0]} />
        <meshBasicMaterial color="#a48bff" transparent opacity={0.5} toneMapped={false} />
      </mesh>
      <Glow color="#8b5cff" scale={2.4} opacity={0.4} />
      <Label
        text={shortName(name, 30)}
        color="#c9b8ff"
        position={[0, 0.9, 0]}
        scale={0.74}
        opacity={0.85}
      />
    </group>
  )
}

function IpSystem({
  node,
  selection,
  onSelect,
  onHover,
  vulnerablePorts,
  vulnerable,
  dimmed,
}: {
  node: IpLayout
  selection: Selection
  onSelect: (selection: Selection) => void
  onHover: (text: string | null) => void
  vulnerablePorts: Set<string>
  vulnerable: boolean
  dimmed: boolean
}) {
  const body = useRef<THREE.Mesh>(null)
  const vulnCount = node.open.filter((port) =>
    vulnerablePorts.has(cveKey(node.entry.ip, port.info.port, port.info.protocol)),
  ).length
  const handlers = useHoverHandlers(
    onHover,
    `${node.entry.ip} · ${node.open.length} open${vulnCount ? ` · ${vulnCount} CVE` : ''} · ${shortName(
      node.entry.ptr || node.entry.geo?.city || 'resolved host',
      26,
    )}`,
  )

  const selected =
    (selection?.kind === 'ip' && selection.ip === node.entry.ip) ||
    (selection?.kind === 'port' && selection.ip === node.entry.ip)

  const localPorts = useMemo(
    () =>
      node.ports.map((port) => ({
        info: port.info,
        local: port.pos.clone().sub(node.pos),
      })),
    [node],
  )

  const closedPoints = useMemo(() => {
    const closed = localPorts.filter((port) => port.info.state !== 'open')
    const positions = new Float32Array(closed.length * 3)
    const colors = new Float32Array(closed.length * 3)
    const closedColor = new THREE.Color('#ff3d61')
    const filteredColor = new THREE.Color('#7a8498')

    closed.forEach((port, index) => {
      positions[index * 3] = port.local.x
      positions[index * 3 + 1] = port.local.y
      positions[index * 3 + 2] = port.local.z
      const color = port.info.state === 'filtered' ? filteredColor : closedColor
      colors[index * 3] = color.r
      colors[index * 3 + 1] = color.g
      colors[index * 3 + 2] = color.b
    })

    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3))
    return geometry
  }, [localPorts])

  useFrame(({ clock }) => {
    if (body.current) {
      body.current.rotation.y = clock.elapsedTime * 0.35
      body.current.rotation.x = Math.sin(clock.elapsedTime * 0.4) * 0.15
    }
  })

  const onClick = (event: ThreeEvent<MouseEvent>) => {
    event.stopPropagation()
    onSelect({ kind: 'ip', ip: node.entry.ip })
  }

  const portLabelLimit = node.open.length <= 18 ? node.open.length : 12

  return (
    <group position={node.pos}>
      <mesh position={[0, -node.pos.y / 2, 0]}>
        <cylinderGeometry args={[0.035, 0.035, node.pos.y, 6]} />
        <meshBasicMaterial
          color="#38f6ff"
          transparent
          opacity={dimmed ? 0.04 : 0.18}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
          toneMapped={false}
        />
      </mesh>

      <mesh ref={body} {...handlers} onClick={onClick} scale={selected ? 1.25 : 1}>
        <octahedronGeometry args={[0.72, 0]} />
        <meshBasicMaterial
          color={vulnerable ? '#ff3b5c' : node.entry.primary ? '#38f6ff' : '#91a9ff'}
          wireframe
          transparent
          opacity={dimmed ? 0.12 : 0.95}
          toneMapped={false}
        />
      </mesh>
      <mesh scale={0.34} onClick={onClick} {...handlers}>
        <octahedronGeometry args={[0.72, 0]} />
        <meshBasicMaterial
          color={vulnerable ? '#ff3b5c' : node.entry.primary ? '#38f6ff' : '#91a9ff'}
          transparent
          opacity={dimmed ? 0.06 : 0.55}
          toneMapped={false}
        />
      </mesh>

      <Glow
        color={vulnerable ? '#ff3b5c' : '#38f6ff'}
        scale={4.6}
        opacity={dimmed ? 0.05 : vulnerable ? 0.7 : 0.5}
      />
      {vulnerable && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[1.55, 0.028, 8, 96]} />
          <meshBasicMaterial
            color="#ff3b5c"
            transparent
            opacity={dimmed ? 0.12 : 0.85}
            toneMapped={false}
          />
        </mesh>
      )}
      {selected && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[2.1, 0.02, 8, 120]} />
          <meshBasicMaterial color="#ffffff" transparent opacity={0.7} toneMapped={false} />
        </mesh>
      )}

      <Label
        text={shortName(node.entry.ip, 22)}
        color={node.entry.primary ? '#7fe9ff' : '#aebcff'}
        position={[0, 1.45, 0]}
        scale={1.28}
        opacity={dimmed ? 0.14 : 1}
      />
      <Label
        text={shortName(node.entry.ptr || node.entry.geo?.city || `IPv${node.entry.family}`, 24)}
        color="#6aa6b8"
        position={[0, 0.84, 0]}
        scale={0.7}
        opacity={dimmed ? 0.1 : 0.85}
      />

      <points geometry={closedPoints}>
        <pointsMaterial
          size={0.17}
          vertexColors
          transparent
          opacity={dimmed ? 0.08 : 0.85}
          sizeAttenuation
          depthWrite={false}
          toneMapped={false}
        />
      </points>

      {node.open.map((port, index) => {
        const local = port.pos.clone().sub(node.pos)
        const udp = port.info.protocol === 'udp'
        const isVulnerable = vulnerablePorts.has(
          cveKey(node.entry.ip, port.info.port, port.info.protocol),
        )
        const accent = isVulnerable ? '#ff3b5c' : udp ? '#ffb020' : '#49ff9e'
        const isSelected =
          selection?.kind === 'port' &&
          selection.ip === node.entry.ip &&
          selection.port === port.info.port &&
          (selection.protocol ?? 'tcp') === port.info.protocol
        return (
          <group key={`${port.info.protocol}:${port.info.port}`}>
            <Line
              points={[new THREE.Vector3(0, 0, 0), local]}
              color={accent}
              lineWidth={0.6}
              transparent
              opacity={dimmed ? 0.04 : 0.22}
            />
            <mesh
              position={local}
              scale={isSelected ? 1.8 : 1}
              onClick={(event) => {
                event.stopPropagation()
                onSelect({
                  kind: 'port',
                  ip: node.entry.ip,
                  port: port.info.port,
                  protocol: port.info.protocol,
                })
              }}
              onPointerOver={(event) => {
                event.stopPropagation()
                onHover(
                  `${node.entry.ip}:${port.info.port} ${port.info.protocol.toUpperCase()} OPEN · ${
                    port.info.service || 'service'
                  }`,
                )
                document.body.style.cursor = 'pointer'
              }}
              onPointerOut={(event) => {
                event.stopPropagation()
                onHover(null)
                document.body.style.cursor = 'default'
              }}
            >
              <octahedronGeometry args={[0.24, 0]} />
              <meshBasicMaterial
                color={isSelected ? '#ffffff' : accent}
                transparent
                opacity={dimmed ? 0.12 : 0.98}
                toneMapped={false}
              />
            </mesh>
            <Glow
              color={accent}
              scale={1.1}
              position={[local.x, local.y, local.z]}
              opacity={dimmed ? 0.05 : 0.5}
            />
            {index < portLabelLimit && (
              <Label
                text={`:${port.info.port}${udp ? '/u' : ''}`}
                color={isVulnerable ? '#ff9baf' : udp ? '#ffd291' : '#7dffc0'}
                position={[local.x, local.y + 0.4, local.z]}
                scale={0.62}
                opacity={dimmed ? 0.08 : 0.9}
              />
            )}
          </group>
        )
      })}
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  DNS nodes                                                          */
/* ------------------------------------------------------------------ */

function DnsLink({
  from,
  to,
  kind,
}: {
  from: THREE.Vector3
  to: THREE.Vector3
  kind: 'ns' | 'mx'
}) {
  const points = useMemo(() => ipLinkPoints(from, to), [from, to])
  return (
    <Line
      points={points}
      color={kind === 'ns' ? '#ffb020' : '#c07bff'}
      lineWidth={0.8}
      dashed
      dashSize={0.55}
      gapSize={0.4}
      transparent
      opacity={0.3}
      toneMapped={false}
    />
  )
}

function DnsNode({
  node,
  kind,
  index,
  selected,
  onSelect,
  onHover,
}: {
  node: DnsNodeLayout
  kind: 'ns' | 'mx'
  index: number
  selected: boolean
  onSelect: (selection: Selection) => void
  onHover: (text: string | null) => void
}) {
  const mesh = useRef<THREE.Mesh>(null)
  const color = kind === 'ns' ? '#ffb020' : '#c07bff'
  const label = kind === 'ns' ? node.name : node.name
  const displayName = label.includes('.') ? label.slice(0, label.indexOf('.')) : label
  const handlers = useHoverHandlers(onHover, `${kind.toUpperCase()} · ${label}`)

  useFrame(({ clock }) => {
    if (!mesh.current) return
    mesh.current.rotation.y = clock.elapsedTime * (kind === 'ns' ? 0.45 : 0.3)
    mesh.current.rotation.x = Math.sin(clock.elapsedTime * 0.5 + index) * 0.2
  })

  const onClick = (event: ThreeEvent<MouseEvent>) => {
    event.stopPropagation()
    onSelect(kind === 'ns' ? { kind: 'ns', index } : { kind: 'mx', index })
  }

  return (
    <group position={node.pos}>
      <mesh ref={mesh} scale={selected ? 1.5 : 1} {...handlers} onClick={onClick}>
        {kind === 'ns' ? (
          <tetrahedronGeometry args={[0.62, 0]} />
        ) : (
          <octahedronGeometry args={[0.55, 0]} />
        )}
        <meshBasicMaterial color={color} wireframe transparent opacity={0.95} toneMapped={false} />
      </mesh>
      <mesh scale={0.26} onClick={onClick} {...handlers}>
        {kind === 'ns' ? (
          <tetrahedronGeometry args={[0.62, 0]} />
        ) : (
          <octahedronGeometry args={[0.55, 0]} />
        )}
        <meshBasicMaterial color={color} transparent opacity={0.5} toneMapped={false} />
      </mesh>
      <Glow color={color} scale={kind === 'ns' ? 3.4 : 3} opacity={0.5} />
      {selected && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[1.5, 0.015, 6, 100]} />
          <meshBasicMaterial color="#ffffff" transparent opacity={0.7} toneMapped={false} />
        </mesh>
      )}
      <Label
        text={shortName(displayName, 16)}
        color={kind === 'ns' ? '#ffc861' : '#d3a4ff'}
        position={[0, 1.12, 0]}
        scale={0.98}
      />
      <Label text={node.sub || ''} color="#7f8ea3" position={[0, 0.6, 0]} scale={0.58} opacity={0.8} />
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  route hops                                                         */
/* ------------------------------------------------------------------ */

function HopNode({
  node,
  selected,
  onSelect,
  onHover,
}: {
  node: HopLayout
  selected: boolean
  onSelect: (selection: Selection) => void
  onHover: (text: string | null) => void
}) {
  const mesh = useRef<THREE.Mesh>(null)
  const { hop } = node
  const color = hop.ip ? '#ff6bd6' : '#ff3d61'
  const text = hop.ip || '***'
  const handlers = useHoverHandlers(
    onHover,
    `HOP ${hop.index} · ${text}${hop.geo?.city ? ` · ${hop.geo.city}` : ''}`,
  )

  useFrame(({ clock }) => {
    if (!mesh.current) return
    mesh.current.rotation.y = clock.elapsedTime * 0.7 + hop.index
    mesh.current.rotation.x = clock.elapsedTime * 0.35
  })

  const onClick = (event: ThreeEvent<MouseEvent>) => {
    event.stopPropagation()
    onSelect({ kind: 'hop', index: hop.index })
  }

  return (
    <group position={node.pos}>
      <mesh ref={mesh} scale={selected ? 1.7 : 1} {...handlers} onClick={onClick}>
        <boxGeometry args={[0.38, 0.38, 0.38]} />
        <meshBasicMaterial
          color={color}
          wireframe
          transparent
          opacity={hop.ip ? 0.95 : 0.6}
          toneMapped={false}
        />
      </mesh>
      <mesh scale={0.12}>
        <boxGeometry args={[0.38, 0.38, 0.38]} />
        <meshBasicMaterial color={color} toneMapped={false} />
      </mesh>
      <Glow color={color} scale={1.6} opacity={0.42} />
      <Label
        text={shortName(text, 20)}
        color={hop.ip ? '#ff9bea' : '#ff6b7f'}
        position={[hop.index % 2 === 0 ? 1.1 : -1.1, 0.72, 0]}
        scale={0.76}
        opacity={0.92}
      />
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  local origin & scan wave                                           */
/* ------------------------------------------------------------------ */

function YouNode({
  position,
  selected,
  onSelect,
  onHover,
}: {
  position: THREE.Vector3
  selected: boolean
  onSelect: (selection: Selection) => void
  onHover: (text: string | null) => void
}) {
  const ring = useRef<THREE.Mesh>(null)
  const handlers = useHoverHandlers(onHover, 'YOU · local origin')

  useFrame(({ clock }) => {
    if (!ring.current) return
    ring.current.rotation.z = clock.elapsedTime * 0.5
  })

  return (
    <group position={position}>
      <mesh
        onClick={(event) => {
          event.stopPropagation()
          onSelect({ kind: 'you' })
        }}
        {...handlers}
        scale={selected ? 1.4 : 1}
      >
        <icosahedronGeometry args={[0.38, 0]} />
        <meshBasicMaterial color="#ffffff" wireframe transparent opacity={0.9} toneMapped={false} />
      </mesh>
      <mesh ref={ring} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[1.1, 0.02, 8, 90]} />
        <meshBasicMaterial color="#38f6ff" transparent opacity={0.65} toneMapped={false} />
      </mesh>
      <Glow color="#9beeff" scale={3.4} opacity={0.42} />
      <Label text="YOU" color="#d9fbff" position={[0, 1.05, 0]} scale={1} />
      <mesh position={[0, -position.y / 2, 0]}>
        <cylinderGeometry args={[0.02, 0.02, position.y, 6]} />
        <meshBasicMaterial
          color="#38f6ff"
          transparent
          opacity={0.16}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
          toneMapped={false}
        />
      </mesh>
    </group>
  )
}

function ScanPulse({ position }: { position: THREE.Vector3 }) {
  const rings = useRef<(THREE.Mesh | null)[]>([])
  const materials = useRef<(THREE.MeshBasicMaterial | null)[]>([])

  useFrame(({ clock }) => {
    const t = clock.elapsedTime
    rings.current.forEach((ring, index) => {
      if (!ring) return
      const progress = (t * 0.35 + index / 3) % 1
      const scale = 1 + progress * 16
      ring.scale.setScalar(scale)
      const material = materials.current[index]
      if (material) material.opacity = 0.32 * (1 - progress)
    })
  })

  return (
    <group position={position}>
      {[0, 1, 2].map((index) => (
        <mesh
          key={index}
          rotation={[Math.PI / 2, 0, 0]}
          ref={(el) => {
            rings.current[index] = el
            if (el) materials.current[index] = el.material as THREE.MeshBasicMaterial
          }}
        >
          <torusGeometry args={[1.3, 0.018, 6, 120]} />
          <meshBasicMaterial
            color="#38f6ff"
            transparent
            opacity={0.3}
            depthWrite={false}
            blending={THREE.AdditiveBlending}
            toneMapped={false}
          />
        </mesh>
      ))}
    </group>
  )
}