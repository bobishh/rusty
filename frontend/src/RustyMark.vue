<script setup lang="ts">
import rustyLogo from "./assets/rusty-logo.webp"
withDefaults(defineProps<{ online?: boolean; reconnecting?: boolean; compact?: boolean }>(), { online: false, reconnecting: false, compact: false })
</script>

<template>
  <img :src="rustyLogo" class="rusty-mark" :class="{ 'is-online': online, 'is-reconnecting': reconnecting, 'is-compact': compact }" alt="Rusty" width="32" height="40" />
</template>
