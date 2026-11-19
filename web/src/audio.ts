/**
 * Cyberpunk audio engine on top of the Web Audio API.
 *
 * Off by default, remembered in localStorage. The ambient pad and every SFX
 * are synthesised locally: no audio files are downloaded and no third-party
 * tracker is involved.
 */

export type Sfx = 'click' | 'port' | 'alarm' | 'warp' | 'toggle'

const STORAGE_KEY = 'network-map:sound'

class AudioEngine {
  private context: AudioContext | null = null
  private master: GainNode | null = null
  private ambientGain: GainNode | null = null
  private ambientNodes: OscillatorNode[] = []
  private enabled = false
  private armed = false
  private persist = true

  get on() {
    return this.enabled
  }

  readPreference(): boolean {
    if (typeof window === 'undefined') return false
    try {
      return window.localStorage.getItem(STORAGE_KEY) === 'on'
    } catch {
      return false
    }
  }

  setEnabled(value: boolean) {
    this.enabled = value
    if (this.persist && typeof window !== 'undefined') {
      try {
        window.localStorage.setItem(STORAGE_KEY, value ? 'on' : 'off')
      } catch {}
    }
    if (typeof window === 'undefined') return
    if (value) {
      this.ensure()
      this.startAmbient()
    } else {
      this.stopAmbient()
    }
  }

  toggle(): boolean {
    const next = !this.enabled
    this.setEnabled(next)
    if (next) this.play('toggle')
    return next
  }

  private ensure(): AudioContext | null {
    if (typeof window === 'undefined') return null
    if (!this.context) {
      const ctor =
        window.AudioContext ||
        (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
      if (!ctor) return null
      try {
        this.context = new ctor()
      } catch {
        return null
      }
      this.master = this.context.createGain()
      this.master.gain.value = 0.85
      this.master.connect(this.context.destination)
    }

    if (this.context.state === 'suspended') {
      void this.context.resume().catch(() => {})
      // Browsers block audio until a gesture: resume once the user clicks.
      if (!this.armed) {
        this.armed = true
        const resume = () => {
          void this.context?.resume().catch(() => {})
          window.removeEventListener('pointerdown', resume)
        }
        window.addEventListener('pointerdown', resume, { once: true })
      }
    }
    return this.context
  }

  private startAmbient() {
    const ctx = this.ensure()
    if (!ctx || !this.master || this.ambientGain) return

    const gain = ctx.createGain()
    gain.gain.setValueAtTime(0.0001, ctx.currentTime)
    gain.connect(this.master)

    const filter = ctx.createBiquadFilter()
    filter.type = 'lowpass'
    filter.frequency.value = 430
    filter.Q.value = 2.4
    filter.connect(gain)

    const sub = ctx.createOscillator()
    sub.type = 'sine'
    sub.frequency.value = 55
    const fifth = ctx.createOscillator()
    fifth.type = 'triangle'
    fifth.frequency.value = 82.41
    fifth.detune.value = -7
    const shimmer = ctx.createOscillator()
    shimmer.type = 'sine'
    shimmer.frequency.value = 220
    shimmer.detune.value = 5
    const shimmerGain = ctx.createGain()
    shimmerGain.gain.value = 0.09

    sub.connect(filter)
    fifth.connect(filter)
    shimmer.connect(shimmerGain)
    shimmerGain.connect(gain)

    const lfo = ctx.createOscillator()
    lfo.type = 'sine'
    lfo.frequency.value = 0.07
    const lfoGain = ctx.createGain()
    lfoGain.gain.value = 170
    lfo.connect(lfoGain)
    lfoGain.connect(filter.frequency)

    sub.start()
    fifth.start()
    shimmer.start()
    lfo.start()
    gain.gain.linearRampToValueAtTime(0.15, ctx.currentTime + 2.6)

    this.ambientGain = gain
    this.ambientNodes = [sub, fifth, shimmer, lfo]
  }

  private stopAmbient() {
    const ctx = this.context
    if (!ctx || !this.ambientGain) return
    const gain = this.ambientGain
    const nodes = this.ambientNodes
    this.ambientGain = null
    this.ambientNodes = []
    try {
      gain.gain.cancelScheduledValues(ctx.currentTime)
      gain.gain.setValueAtTime(gain.gain.value, ctx.currentTime)
      gain.gain.linearRampToValueAtTime(0.0001, ctx.currentTime + 0.25)
    } catch {}
    window.setTimeout(() => {
      for (const node of nodes) {
        try {
          node.stop()
          node.disconnect()
        } catch {}
      }
      try {
        gain.disconnect()
      } catch {}
    }, 320)
  }

  private tone(
    type: OscillatorType,
    from: number,
    to: number,
    duration: number,
    volume: number,
    delay = 0,
  ) {
    const ctx = this.ensure()
    if (!ctx || !this.master) return
    const start = ctx.currentTime + delay
    const osc = ctx.createOscillator()
    const gain = ctx.createGain()
    osc.type = type
    osc.frequency.setValueAtTime(Math.max(20, from), start)
    osc.frequency.exponentialRampToValueAtTime(Math.max(20, to), start + duration)
    gain.gain.setValueAtTime(0.0001, start)
    gain.gain.exponentialRampToValueAtTime(volume, start + Math.min(0.03, duration / 3))
    gain.gain.exponentialRampToValueAtTime(0.0001, start + duration)
    osc.connect(gain)
    gain.connect(this.master)
    osc.start(start)
    osc.stop(start + duration + 0.03)
    osc.onended = () => {
      try {
        osc.disconnect()
        gain.disconnect()
      } catch {}
    }
  }

  play(sfx: Sfx) {
    if (!this.enabled) return
    if (!this.ensure()) return
    switch (sfx) {
      case 'click':
        this.tone('square', 1250, 720, 0.055, 0.035)
        break
      case 'port':
        this.tone('sine', 520, 540, 0.08, 0.08)
        this.tone('sine', 780, 1040, 0.16, 0.06, 0.07)
        break
      case 'alarm':
        this.tone('sawtooth', 220, 220, 0.16, 0.08)
        this.tone('sawtooth', 330, 330, 0.16, 0.07, 0.2)
        this.tone('sawtooth', 220, 220, 0.16, 0.08, 0.4)
        break
      case 'warp':
        this.tone('sawtooth', 72, 880, 1.5, 0.1)
        this.tone('square', 144, 1760, 1.35, 0.045, 0.08)
        this.tone('sine', 60, 300, 1.7, 0.12)
        break
      case 'toggle':
        this.tone('sine', 660, 990, 0.12, 0.06)
        break
    }
  }
}

export const audio = new AudioEngine()
