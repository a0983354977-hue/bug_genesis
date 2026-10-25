import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { KIND_COLORS, type Family, type Kb } from "./kb";

/**
 * 3D layout of the bug families.
 *
 * Axes are chosen so that every position means something, because a
 * force-directed layout over families has no edges to act on and would just
 * produce a hairball:
 *
 *   x — discovery time (bug_families.first_seen)
 *   y — defect class  (kind_label | code)
 *   z — the strategy that produced most of that family's cases
 *
 * Node radius is sqrt(hit_count), so area tracks hits rather than radius
 * flattering a long tail.
 */

export interface GraphApi {
  setData(kb: Kb): void;
  setProgress(fraction: number): void;
  highlight(id: string | null): void;
  dispose(): void;
}

interface Node {
  family: Family;
  mesh: THREE.Mesh;
  lane: number;
  strategyLane: number;
}

const LANE_H = 2.6;
const STRAT_D = 3.2;
const X_HALF = 26;

function makeLabel(text: string, size = 44, color = "#8b93a5"): THREE.Sprite {
  const pad = 10;
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d")!;
  ctx.font = `${size}px "Segoe UI", system-ui, sans-serif`;
  const w = Math.ceil(ctx.measureText(text).width) + pad * 2;
  canvas.width = Math.max(8, w);
  canvas.height = size + pad * 2;
  const c2 = canvas.getContext("2d")!;
  c2.font = `${size}px "Segoe UI", system-ui, sans-serif`;
  c2.fillStyle = color;
  c2.textBaseline = "middle";
  c2.fillText(text, pad, canvas.height / 2);

  const tex = new THREE.CanvasTexture(canvas);
  tex.anisotropy = 4;
  const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
  const sprite = new THREE.Sprite(mat);
  const scale = 0.012;
  sprite.scale.set(canvas.width * scale, canvas.height * scale, 1);
  return sprite;
}

export function createGraph(
  canvas: HTMLCanvasElement,
  onSelect: (family: Family) => void,
  onStatus: (text: string, tone?: "good" | "bad") => void,
): GraphApi {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x0b0d12);
  scene.fog = new THREE.Fog(0x0b0d12, 60, 130);

  const camera = new THREE.PerspectiveCamera(52, 1, 0.1, 400);
  camera.position.set(0, 14, 46);

  const controls = new OrbitControls(camera, canvas);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;

  scene.add(new THREE.AmbientLight(0xffffff, 0.75));
  const key = new THREE.DirectionalLight(0xffffff, 1.1);
  key.position.set(18, 28, 20);
  scene.add(key);

  const grid = new THREE.GridHelper(100, 40, 0x1b2130, 0x151a26);
  grid.position.y = -1.4;
  scene.add(grid);

  const root = new THREE.Group();
  scene.add(root);

  const sphereGeo = new THREE.SphereGeometry(1, 20, 14);
  const nodes: Node[] = [];
  const byId = new Map<string, Node>();
  const lanes: THREE.Group[] = [];
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  let selected: string | null = null;
  let hovered: Node | null = null;
  let disposed = false;

  function clear() {
    // NOTE: `sphereGeo` is deliberately NOT disposed here. setData() clears and
    // rebuilds on every load, and cloning a disposed geometry renders nothing —
    // a silent black canvas with no error anywhere. It is disposed in dispose().
    for (const n of nodes) {
      root.remove(n.mesh);
      n.mesh.geometry.dispose();
      (n.mesh.material as THREE.Material).dispose();
    }
    nodes.length = 0;
    byId.clear();
    for (const lane of lanes) {
      root.remove(lane);
      lane.traverse((o) => {
        if ((o as THREE.Sprite).isSprite) {
          const s = o as THREE.Sprite;
          s.material.map?.dispose();
          s.material.dispose();
        }
      });
    }
    lanes.length = 0;
  }

  function setData(kb: Kb) {
    clear();
    if (!kb.families.length) {
      onStatus("知識庫沒有任何 bug_families —— campaign 可能還沒寫入就被中斷。", "bad");
      return;
    }

    const laneIndex = new Map(kb.classes.map((c, i) => [c, i]));
    const strategies = kb.strategies.length ? kb.strategies : ["(unknown)"];
    const stratIndex = new Map(strategies.map((s, i) => [s, i]));

    const times = kb.families.map((f) => f.firstSeenMs).filter((t) => t > 0);
    const t0 = times.length ? Math.min(...times) : 0;
    const t1 = times.length ? Math.max(...times) : 1;
    const span = Math.max(1, t1 - t0);
    const maxHits = Math.max(1, ...kb.families.map((f) => f.hitCount));

    // One group per defect class, so lane labels and guides stay together.
    for (const cls of kb.classes) {
      const lane = new THREE.Group();
      const y = (laneIndex.get(cls) ?? 0) * LANE_H;
      const guide = new THREE.Mesh(
        new THREE.BoxGeometry(X_HALF * 2, 0.02, 0.02),
        new THREE.MeshBasicMaterial({ color: 0x1f2634 }),
      );
      guide.position.set(0, y, 0);
      lane.add(guide);

      const label = makeLabel(cls.replace("|", " · "), 40);
      label.position.set(-X_HALF - 2.5, y, 0);
      lane.add(label);

      root.add(lane);
      lanes.push(lane);
    }

    // Time axis ticks, so the x axis is readable without hovering.
    const axis = new THREE.Group();
    for (let i = 0; i <= 4; i++) {
      const t = t0 + (span * i) / 4;
      const x = -X_HALF + (X_HALF * 2 * i) / 4;
      const label = makeLabel(new Date(t).toISOString().slice(11, 19), 34, "#5b6478");
      label.position.set(x, -1.1, 6);
      axis.add(label);
    }
    root.add(axis);
    lanes.push(axis);

    for (const family of kb.families) {
      const lane = laneIndex.get(family.classKey) ?? 0;
      const sLane = stratIndex.get(family.topStrategy) || 0;
      const frac = family.firstSeenMs > 0 ? (family.firstSeenMs - t0) / span : 0.5;

      const radius = 0.3 + 1.0 * Math.sqrt(family.hitCount / maxHits);
      const mesh = new THREE.Mesh(
        sphereGeo.clone(),
        new THREE.MeshStandardMaterial({
          color: KIND_COLORS[family.kindLabel] ?? 0x9ca3af,
          roughness: 0.45,
          metalness: 0.1,
          emissive: 0x000000,
        }),
      );
      mesh.position.set(
        -X_HALF + frac * X_HALF * 2,
        lane * LANE_H,
        (sLane - (strategies.length - 1) / 2) * STRAT_D,
      );
      mesh.scale.setScalar(radius);
      mesh.userData.family = family;
      root.add(mesh);

      const node: Node = { family, mesh, lane, strategyLane: sLane };
      nodes.push(node);
      byId.set(family.id, node);
    }

    // Centre the camera on the data rather than on the world origin.
    const centreY = ((kb.classes.length - 1) * LANE_H) / 2;
    controls.target.set(0, centreY, 0);
    camera.position.set(0, centreY + 12, 44);
    controls.update();
    setProgress(1);
    onStatus(
      `已載入 ${kb.label} — ${kb.families.length} 個族群 / ${kb.cases.length} 筆案例 / ${kb.bytes.toLocaleString()} bytes`,
      "good",
    );
  }

  let progress = 1;
  function setProgress(fraction: number) {
    progress = Math.max(0, Math.min(1, fraction));
    // Reveal by index in discovery order: setData() sorts families by
    // first_seen, so a fraction is a prefix of the list in time order.
    const cut = Math.round(nodes.length * progress);
    for (let i = 0; i < nodes.length; i++) nodes[i].mesh.visible = i < cut;
    if (selected) highlight(selected, false);
  }

  function highlight(id: string | null, moveCamera = false) {
    selected = id;
    for (const n of nodes) {
      const mat = n.mesh.material as THREE.MeshStandardMaterial;
      const on = n.family.id === id;
      mat.emissive.setHex(on ? 0x224444 : 0x000000);
      n.mesh.renderOrder = on ? 1 : 0;
    }
    if (moveCamera && id) {
      const node = byId.get(id);
      if (node) {
        controls.target.copy(node.mesh.position);
        camera.position.set(
          node.mesh.position.x + 6,
          node.mesh.position.y + 5,
          node.mesh.position.z + 14,
        );
        controls.update();
      }
    }
  }

  function pick(ev: PointerEvent): Node | null {
    const rect = canvas.getBoundingClientRect();
    pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(pointer, camera);
    const hits = raycaster.intersectObjects(nodes.map((n) => n.mesh), false);
    const first = hits.find((h) => h.object.visible);
    return first ? (byId.get((first.object.userData.family as Family).id) ?? null) : null;
  }

  function onMove(ev: PointerEvent) {
    const node = pick(ev);
    if (node !== hovered) {
      hovered = node;
      canvas.style.cursor = node ? "pointer" : "grab";
      if (node) {
        onStatus(
          `[${node.family.kindLabel}] ${shortSig(node.family.signature)} — hits=${node.family.hitCount}, repro=${node.family.reproLen}B`,
        );
      }
    }
  }

  function onClick(ev: PointerEvent) {
    const node = pick(ev);
    if (!node) return;
    highlight(node.family.id, true);
    onSelect(node.family);
  }

  function shortSig(sig: string): string {
    const parts = sig.split("|");
    return parts.length >= 3 ? parts[2] : sig;
  }

  canvas.addEventListener("pointermove", onMove);
  canvas.addEventListener("click", onClick);

  function resize() {
    // Clamp, and refuse nonsense. A zero or runaway measurement would otherwise
    // be handed straight to the GPU: at pixelRatio 2 a 191662x883 backing store
    // is ~338 million pixels, which does not fail loudly — it just takes the
    // tab down with the WebGL context.
    const clamp = (v: number) => (Number.isFinite(v) && v > 1 ? Math.min(v, 4096) : 1);
    const w = clamp(canvas.clientWidth || canvas.parentElement?.clientWidth || 0);
    const h = clamp(canvas.clientHeight || canvas.parentElement?.clientHeight || 0);
    if (w === 1 || h === 1) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  const ro = new ResizeObserver(resize);
  ro.observe(canvas);
  resize();

  function frame() {
    if (disposed) return;
    requestAnimationFrame(frame);
    controls.update();
    renderer.render(scene, camera);
  }
  frame();

  return {
    setData,
    setProgress,
    highlight,
    dispose() {
      disposed = true;
      ro.disconnect();
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("click", onClick);
      clear();
      sphereGeo.dispose();
      controls.dispose();
      renderer.dispose();
    },
  };
}
