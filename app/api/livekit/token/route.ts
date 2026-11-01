import { NextRequest, NextResponse } from 'next/server'
import { AccessToken } from 'livekit-server-sdk'
import { createClient } from '@/lib/supabase/server'
import { checkLiveAccess } from '@/lib/live-guard'

export async function POST(request: NextRequest) {
  try {
    const supabase = await createClient()
    const { data: { user }, error } = await supabase.auth.getUser()
    if (error || !user) {
      return NextResponse.json({ success: false, error: 'unauthorized' }, { status: 401 })
    }

    // Authentication alone does not grant access to paid live infrastructure.
    const entitlement = await checkLiveAccess(user.id)
    if (!entitlement.allowed) {
      return NextResponse.json({ success: false, error: 'live access required' }, { status: 403 })
    }

    const body = await request.json()
    const { roomName, participantName, isPublisher } = body ?? {}
    if (typeof roomName !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(roomName) ||
        (participantName !== undefined && (typeof participantName !== 'string' || participantName.length > 128)) ||
        (isPublisher !== undefined && typeof isPublisher !== 'boolean')) {
      return NextResponse.json({ success: false, error: 'invalid request' }, { status: 400 })
    }

    const apiKey = process.env.LIVEKIT_API_KEY
    const apiSecret = process.env.LIVEKIT_API_SECRET
    if (!apiKey || !apiSecret) {
      console.error('[LiveKit] Missing API credentials')
      return NextResponse.json({ success: false, error: 'LiveKit non configure' }, { status: 503 })
    }

    // Never accept a caller-provided identity. Room membership authorization
    // must be enforced separately before enabling sensitive/private rooms.
    const token = new AccessToken(apiKey, apiSecret, {
      identity: user.id,
      name: participantName || user.id,
      ttl: '15m',
    })
    token.addGrant({
      room: roomName,
      roomJoin: true,
      canPublish: isPublisher !== false,
      canSubscribe: true,
      canPublishData: true,
    })

    return NextResponse.json({
      success: true,
      token: await token.toJwt(),
      roomName,
      wsUrl: process.env.LIVEKIT_WS_URL || 'wss://chapcam.livekit.cloud',
    })
  } catch (error) {
    console.error('[LiveKit] Error creating token:', error)
    return NextResponse.json({ success: false, error: 'Erreur creation token' }, { status: 500 })
  }
}
