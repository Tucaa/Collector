(ns collector
  (:gen-class)
  (:require [clojure.java.io :as io])
  (:import [java.util Base64]
           [java.nio ByteBuffer ByteOrder]))

;Konvertovanje bajtova u hexadecimalni string
(defn convert_bytes_hex [array len]
  (apply str (map #(format "%02x" %) (take len array))))

;Konvertovanje bajtovau Base 64 string
(defn convert_bytes_base64 [array len]
  (let [encoder (Base64/getEncoder)]
    (.encodeToString encoder (java.util.Arrays/copyOf array 0 len))))


;F-ja koja cita podatke iz pcap fajla (resiti import) za sada samo binarni format dok ne resis problem sa citanjem preko io.pkts
(defn raw_file [file]
  (with-open [in (io/input-stream file)]
    (loop [buffer (byte-array 4096)]
      (let [n (.read in buffer)]
        (when (pos? n)
          (println (str "Hexadecimal" convert_bytes_hex buffer n))
          (println (str "Base64 " convert_bytes_base64 buffer n))
          ;(println (String. buffer 0 n "ISO-8859-1"))
          (recur buffer))))))

;Funkcija za citanje 32 bitnih podataka

(defn read32 [buffer byte_ord]
  (let [unit (ByteBuffer/wrap buffer)]
    (.order unit byte_ord)
    ;Mora da se konverturje u logn sa samo .getInt unit je bacao integer overflow
    (bit-and (long (.getInt unit)) 0xFFFFFFFF)))

;Funkcija za citanje 16 bitnih podataka
(defn read16 [buffer byte_ord]
  (let [unit (ByteBuffer/wrap buffer)]
    (.order unit byte_ord)
    ;Mora da se konverturje u logn sa samo .getInt unit je bacao integer overflow
    (bit-and (.getShort unit) 0xFFFF)))

;F-ja koja parsira globalni header .pcap fajla
(defn parse_header_global [arr]
  (let [header (byte-array 24)
        n (.read arr header)]
    (when (= n 24)
      (let [read (read32 (java.util.Arrays/copyOfRange header 0 4) ByteOrder/LITTLE_ENDIAN)
            byte_ord (if (or (= read 0xa1b2c3d4) (= read 0xa1b23c4d))
                         ByteOrder/LITTLE_ENDIAN
                         ByteOrder/BIG_ENDIAN)]
        {:read read
         :version_major (read16 (java.util.Arrays/copyOfRange header 4 6) byte_ord)
         :network (read32 (java.util.Arrays/copyOfRange header 20 24) byte_ord)
         :byt_order byte_ord}))))

;Parsiranje zaglavlja paketa
(defn parse_header_packet [arr byte_ord]
  (let [header (byte-array 16)
        n (.read arr header)]
    (when (= n 16)
      {:ts_sec (read32 (java.util.Arrays/copyOfRange header 0 4) byte_ord)
       :ts_usec (read32 (java.util.Arrays/copyOfRange header 4 8) byte_ord)
       :incl_len (read32 (java.util.Arrays/copyOfRange header 8 12) byte_ord)
       :orig_len (read32 (java.util.Arrays/copyOfRange header 12 16) byte_ord)})))

;Parsiranje Ethernet sloja
(defn parse_ethernet [data]
  (when (>= (alength data) 14)
    {:dst_mac (apply str (map #(format "%02x:" %) (take 6 data)))
     :src_mac (apply str (map #(format "%02x:" %) (take 6 (drop 6 data))))
     :ethertype (format "0x%04x" (bit-or (bit-shift-left (bit-and (aget data 12) 0xFF) 8)
                                         (bit-and (aget data 13) 0xFF)))
     :payload (java.util.Arrays/copyOfRange data 14 (alength data))}))

;Parsiranje IP sloja
(defn parse_ip [data]
  (when (>= (alength data) 20)
    (let [version (bit-shift-right (bit-and (aget data 0) 0xFF) 4)
          ihl (bit-and (aget data 0) 0x0F)
          header-len (* ihl 4)
          protocol (bit-and (aget data 9) 0xFF)
          ip_src (format "%d.%d.%d.%d"
                         (bit-and (aget data 12) 0xFF)
                         (bit-and (aget data 13) 0xFF)
                         (bit-and (aget data 14) 0xFF)
                         (bit-and (aget data 15) 0xFF))
          ip_dst (format "%d.%d.%d.%d"
                         (bit-and (aget data 16) 0xFF)
                         (bit-and (aget data 17) 0xFF)
                         (bit-and (aget data 18) 0xFF)
                         (bit-and (aget data 19) 0xFF))]
      {:version version
       :protocol (case protocol
                   1 "ICMP"
                   6 "TCP"
                   17 "UDP"
                   (str "Unknown (" protocol ")"))
       :ip_src ip_src
       :ip_dst ip_dst
       :payload (when (< header-len (alength data))
                  (java.util.Arrays/copyOfRange data header-len (alength data)))})))


;Ovde ce biti logika za parsiranje sFLow podataka
(defn parse_inmon [data]

  )

;Ako se bude islo dublje iskoristiti metodu get-in
(def comp_data {:ip_src [100 200 300 400] :proto [500 500 500]})

;Smisli kako ces da radis agregaciju u loop recuru
;Da li ces na primer ako agregiras po ip_src da pravis hash mapu {:ip_src(ali vrednost) [val1 val2 val3] pa da aggregiras posle to sa reduce
;Ili ces odmah u loop recur to da regulises.
;Trebace ti mapa sa parametrima za agregaciju  npr: {:ip_src [] :ip_dst [] :proto [] ......}
;Definisi vremenski period agregacije (pisanje u fajl)
;Pisanje u fajlu po definisanom rasporedu iz kofiguracije (mape za agregaciju)
;Probaj comp f-ja


(defn agg_byarg [arg data]
  (let [kwkey (keyword arg)
        value (get data kwkey)]
    (if value
      (reduce
        (fn [acc i]
          (+ acc i))
        0
        value)
      0)))


(defn my_filter [f seq]
  (reduce
    (fn [acc e]
      (if (f e)
        (conj acc e)
        acc))
    []
    seq))



;Funkcija koja agregira tot_bytes i koja vraca counter i finalnu agregiranu vrednost
(defn aggregate
  [data]
  (reduce
    (fn [acc item]
      (let [bytes (:tot-bytes item)]
        {:tot_bytes (+ (:tot_bytes acc) bytes)
         :count       (inc (:count acc))}))
    ;Početno stanje akumulatora
    {:tot_bytes 0 :count 0}
    data))

;Funkcija za konvertovanje vrednosti na osnovu definisane jedinice ('KB, MB, GB ...)
;Kasnije modifikovati da dinamicki pronalazi da li su ('KB, MB ili GB)
;Mapirati sa ovom f-jom
(defn convert [unit]
  (let [base 1024]
    (case unit
      :KB (/ bytes base)
      :MB (/ bytes (* base base)) ; 1024^2
      :GB (/ bytes (* base base base)) ; 1024^3
      :TB (/ bytes (* base base base base)) ; 1024^4
      )))


(def test_data
  [{:src-ip "192.168.1.100" :protocol :tcp :tot-bytes 1024}
   {:src-ip "10.0.0.5"      :protocol :udp :tot-bytes 512}
   {:src-ip "192.168.1.100" :protocol :icmp :tot-bytes 128}
   {:src-ip "10.0.0.1"      :protocol :tcp :tot-bytes 2048}])


;Agregirani podaci
(def total_data [:tot_packets :tot_bytes])

(defn -main
  [& args]


  (def test_agg (agg_byarg comp_data)
  ;(def results  (aggregate test_data))

  ;(println (str "Ulazni podaci: " test_data))
  ;(println (str "Rezultati: " results))
  ;(def test_pcap (raw_file "D:/Milan/test.pcap"))


  (def test_header
    (with-open [arr (io/input-stream "D:/Milan/test.pcap")]
      (if-let [header (parse_header_global arr)]
        (do
          (println "____GLOBALNI HEADER_____ ")
          (println (format "Verzija: %d" (:version_major header)))
          (println (format "Mreza: %d" (:network header)))

          (println "_______PAKETI_______")
          (loop [packet_num 1
                 acc_packets 0
                 acc_bytes 0]
            ;Ovde dodati zavrsni uslov empty?

            (if-let [pkt_header (parse_header_packet arr (:byt_order header))]
              (let [packet_data (byte-array (:incl_len pkt_header))
                    n (.read arr packet_data)
                    new_packets (+ acc_packets (:orig_len pkt_header))]

                (when (= n (:incl_len pkt_header))

                  (println (format "--- Packet #%d ---" packet_num))
                  (println (format "Timestamp: %d.%06d" (:ts_sec pkt_header) (:ts_usec pkt_header)))
                  (println (format "Duzina_paketa: %d bytes (captured: %d)"
                                   (:orig_len pkt_header) (:incl_len pkt_header)))

                  (println "_______Ethernet sloj______")
                  (when-let [eth (parse_ethernet packet_data)]
                    (println (format "  Ethernet: %s -> %s (Type: %s)"
                                     (.substring (:src_mac eth) 0 (dec (count (:src_mac eth))))
                                     (.substring (:dst_mac eth) 0 (dec (count (:dst_mac eth))))
                                     (:ethertype eth)))

                    (println "_______IP SLOJ______")
                    (when (= (:ethertype eth) "0x0800")
                      (when-let [ip (parse_ip (:payload eth))]
                        (println (format "  IP: %s -> %s (Protocol: %s)"
                                         (:ip_src ip) (:ip_dst ip) (:protocol ip))))))
                  (println (format "Ukupno paketa %d" new_packets))

                  (recur (inc packet_num) new_packets acc_bytes)))
              (println "Kraj fajla ili nevalidan paket." acc_packets)))))))

  )
