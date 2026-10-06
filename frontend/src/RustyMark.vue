<script setup lang="ts">
import rustyLogo from "./assets/rusty-logo.webp"
withDefaults(defineProps<{ online?: boolean; reconnecting?: boolean; compact?: boolean }>(), { online: false, reconnecting: false, compact: false })
</script>

<template>
  <img :src="rustyLogo" class="rusty-mark" :class="{ 'is-online': online, 'is-reconnecting': reconnecting, 'is-compact': compact }" alt="Rusty" width="32" height="40" />
</template>

<style scoped>
.rusty-mark { display: block; flex: 0 0 32px; width: 32px; height: 40px; object-fit: contain; }
.rusty-mark.is-compact { flex-basis: 24px; width: 24px; height: 30px; }
@media (max-width: 600px) { .rusty-mark:not(.is-compact) { flex-basis: 28px; width: 28px; height: 35px; } }
</style>
