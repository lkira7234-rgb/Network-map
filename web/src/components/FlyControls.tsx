import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { useFrame, useThree } from '@react-three/fiber'

interface FlyControlsProps {
  enabled: boolean
  onExit: () => void
}

/**
 * Free-fly navigation: WASD + mouse look (pointer lock), Space/C for
 * vertical movement, Shift for boost. Falls back to drag-to-look when the
 * browser refuses pointer lock.
 */
export function FlyControls({ enabled, onExit }: FlyControlsProps) {
  const { camera, gl } = useThree()
  const keys = useRef<Record<string, boolean>>({})
  const euler = useRef(new THREE.Euler(0, 0, 0, 'YXZ'))
  const moving = useRef<{ x: number; y: number; active: boolean }>({ x: 0, y: 0, active: false })
  const velocity = useRef(new THREE.Vector3())

  useEffect(() => {
    if (!enabled) return
    const dom = gl.domElement
    euler.current.setFromQuaternion(camera.quaternion, 'YXZ')

    let wasLocked = document.pointerLockElement === dom

    const applyLook = (dx: number, dy: number) => {
      euler.current.y -= dx * 0.0022
      euler.current.x = THREE.MathUtils.clamp(euler.current.x - dy * 0.0022, -1.5, 1.5)
      camera.quaternion.setFromEuler(euler.current)
    }

    const onMouseMove = (event: MouseEvent) => {
      if (document.pointerLockElement !== dom) return
      applyLook(event.movementX, event.movementY)
    }

    const onPointerDown = (event: PointerEvent) => {
      if (document.pointerLockElement === dom) return
      if (event.button !== 0) return
      moving.current = { x: event.clientX, y: event.clientY, active: true }
    }
    const onPointerUp = () => {
      moving.current.active = false
    }
    const onPointerMove = (event: PointerEvent) => {
      if (!moving.current.active || document.pointerLockElement === dom) return
      const dx = event.clientX - moving.current.x
      const dy = event.clientY - moving.current.y
      moving.current.x = event.clientX
      moving.current.y = event.clientY
      applyLook(dx, dy)
    }

    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      if (target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return
      keys.current[event.code] = true
      if (['Space', 'KeyW', 'KeyA', 'KeyS', 'KeyD', 'KeyC', 'ShiftLeft', 'ShiftRight'].includes(event.code)) {
        event.preventDefault()
      }
    }
    const onKeyUp = (event: KeyboardEvent) => {
      keys.current[event.code] = false
    }

    const onLockChange = () => {
      const locked = document.pointerLockElement === dom
      if (wasLocked && !locked) onExit()
      wasLocked = locked
    }

    const onCanvasClick = () => {
      if (document.pointerLockElement !== dom) {
        dom.requestPointerLock?.()
      }
    }

    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('pointerlockchange', onLockChange)
    dom.addEventListener('pointerdown', onPointerDown)
    dom.addEventListener('click', onCanvasClick)
    window.addEventListener('pointerup', onPointerUp)
    window.addEventListener('pointermove', onPointerMove)
    window.addEventListener('keydown', onKeyDown)
    window.addEventListener('keyup', onKeyUp)

    return () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('pointerlockchange', onLockChange)
      dom.removeEventListener('pointerdown', onPointerDown)
      dom.removeEventListener('click', onCanvasClick)
      window.removeEventListener('pointerup', onPointerUp)
      window.removeEventListener('pointermove', onPointerMove)
      window.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('keyup', onKeyUp)
      keys.current = {}
      if (document.pointerLockElement === dom) {
        document.exitPointerLock?.()
      }
    }
  }, [enabled, camera, gl, onExit])

  useFrame((_, delta) => {
    if (!enabled) return

    const dt = Math.min(delta, 0.05)
    const boost = keys.current['ShiftLeft'] || keys.current['ShiftRight'] ? 3.2 : 1
    const speed = 24 * boost * dt

    const forward = new THREE.Vector3()
    camera.getWorldDirection(forward)
    const right = new THREE.Vector3().crossVectors(forward, camera.up).normalize()
    const up = camera.up.clone().normalize()

    const dir = new THREE.Vector3()
    if (keys.current['KeyW']) dir.add(forward)
    if (keys.current['KeyS']) dir.sub(forward)
    if (keys.current['KeyD']) dir.add(right)
    if (keys.current['KeyA']) dir.sub(right)
    if (keys.current['Space']) dir.add(up)
    if (keys.current['KeyC']) dir.sub(up)
    if (keys.current['KeyQ']) dir.add(right)
    if (keys.current['KeyE']) dir.sub(right)

    if (dir.lengthSq() > 0) {
      dir.normalize()
      velocity.current.lerp(dir.multiplyScalar(speed), 0.35)
    } else {
      velocity.current.multiplyScalar(0.82)
    }

    camera.position.add(velocity.current)
    camera.position.y = Math.max(1.2, camera.position.y)
  })

  return null
}